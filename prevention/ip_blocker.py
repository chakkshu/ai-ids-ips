"""Common firewall adapter contract and prevention service layer.

All firewall execution is dry-run unless explicitly enabled by BOTH settings and
capture mode. Real enforcement always uses argument lists with ``shell=False``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import platform
import subprocess  # nosec B404
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Self

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from core.db import ScopedSession
from core.logging import get_correlation_id, get_logger
from core.models.prevention import (
    BlockedIP,
    BlockStatus,
    PreventionAction,
    PreventionActionType,
    Whitelist,
)
from core.models.user import User, UserRole
from core.security import audit_details, log_security_event
from prevention.policy import (
    is_protected_ip,
    is_whitelisted_ip,
    parse_ip,
)

logger = get_logger(__name__)


def _as_utc(value: datetime | None) -> datetime:
    """Normalize ORM timestamps that SQLite returns as naive datetimes."""

    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


RULE_PREFIX = "AI-IDS-"


class PreventionError(RuntimeError):
    """Base class for prevention service failures."""


class ProtectedTargetError(PreventionError):
    """Raised when an operator tries to block a protected address."""


class FirewallActionError(PreventionError):
    """Raised when firewall state could not be safely applied or removed."""


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one adapter operation, including its exact command preview."""

    success: bool
    dry_run: bool
    preview: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: str | None = None

    @property
    def result_label(self) -> str:
        if not self.success:
            return "FAILED"
        return "SIMULATED" if self.dry_run else "SUCCESS"


def execute_firewall_command(command: list[str], *, timeout: int = 10) -> CommandResult:
    """Execute a validated argument list with ``shell=False``.

    This helper is the only place where a real firewall process can start. It
    rechecks every safety prerequisite immediately before execution.
    """

    if not real_enforcement_enabled():
        return CommandResult(
            success=False,
            dry_run=True,
            preview=json.dumps(command, ensure_ascii=True),
            error="real firewall enforcement is disabled",
        )
    if (
        not command
        or not isinstance(command[0], str)
        or any(
            not isinstance(argument, str) or "\x00" in argument for argument in command
        )
    ):
        raise FirewallActionError("invalid firewall command argument list")
    try:
        completed = subprocess.run(  # nosec B603
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(
            success=False,
            dry_run=False,
            preview=json.dumps(command, ensure_ascii=True),
            error=f"firewall command could not complete: {type(exc).__name__}",
        )
    return CommandResult(
        success=completed.returncode == 0,
        dry_run=False,
        preview=json.dumps(command, ensure_ascii=True),
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        returncode=completed.returncode,
    )


class FirewallAdapter(ABC):
    """Interface implemented by every real and dry-run firewall adapter."""

    name = "base"

    @staticmethod
    def rule_name(ip: str) -> str:
        """Return a stable recognizable rule name for an address."""

        digest = hashlib.sha256(parse_ip(ip).packed).hexdigest()[:12]
        return f"{RULE_PREFIX}{digest}"

    @abstractmethod
    def build_block_command(self, ip: str, rule_name: str) -> list[str]:
        """Return the exact argument list that would apply a block."""

    @abstractmethod
    def build_unblock_command(self, ip: str, rule_name: str) -> list[str]:
        """Return the exact argument list that would remove a block."""

    @abstractmethod
    def build_list_command(self) -> list[str]:
        """Return the exact argument list used to list managed rules."""

    @abstractmethod
    def block(self, ip: str, duration_minutes: int) -> CommandResult:
        """Apply (or simulate) a block rule."""

    @abstractmethod
    def unblock(self, ip: str) -> CommandResult:
        """Remove (or simulate) a block rule."""

    @abstractmethod
    def list_rules(self) -> list[str]:
        """List currently managed rule names."""


class DryRunAdapter(FirewallAdapter):
    """Adapter that records commands but never executes them."""

    name = "dry-run"

    def __init__(self, delegate: FirewallAdapter) -> None:
        self.delegate = delegate

    def build_block_command(self, ip: str, rule_name: str) -> list[str]:
        return self.delegate.build_block_command(ip, rule_name)

    def build_unblock_command(self, ip: str, rule_name: str) -> list[str]:
        return self.delegate.build_unblock_command(ip, rule_name)

    def build_list_command(self) -> list[str]:
        return self.delegate.build_list_command()

    @staticmethod
    def _preview(command: list[str]) -> str:
        return json.dumps(command, ensure_ascii=True)

    def block(self, ip: str, duration_minutes: int) -> CommandResult:
        del duration_minutes
        command = self.build_block_command(ip, self.rule_name(ip))
        return CommandResult(
            success=True,
            dry_run=True,
            preview=self._preview(command),
        )

    def unblock(self, ip: str) -> CommandResult:
        command = self.build_unblock_command(ip, self.rule_name(ip))
        return CommandResult(
            success=True,
            dry_run=True,
            preview=self._preview(command),
        )

    def list_rules(self) -> list[str]:
        # In dry-run mode reconciliation simulates the expected state instead
        # of executing a listing command.
        return []


def _platform_adapter() -> FirewallAdapter:
    """Return a real adapter builder for the current OS (never executes)."""

    if platform.system() == "Windows":
        from prevention.firewall_windows import WindowsFirewallAdapter

        return WindowsFirewallAdapter()
    from prevention.firewall_linux import LinuxFirewallAdapter

    return LinuxFirewallAdapter()


def real_enforcement_enabled() -> bool:
    """Return True only when every real-enforcement prerequisite is met."""

    return (
        settings.PREVENTION_MODE == "active"
        and settings.PREVENTION_ALLOW_REAL_ENFORCEMENT
        and not settings.is_simulation_mode()
    )


def get_adapter() -> FirewallAdapter:
    """Return a safe adapter; dry-run is the default and simulation override."""

    adapter = _platform_adapter()
    if real_enforcement_enabled():
        return adapter
    return DryRunAdapter(adapter)


class BlockManager:
    """Service layer for manual and automated block lifecycle operations."""

    def __init__(
        self,
        db_session: Session | None = None,
        adapter: FirewallAdapter | None = None,
        *,
        actor_user_id: int | None = None,
    ) -> None:
        self._owns_session = db_session is None
        self.db = db_session or ScopedSession()
        self.adapter = adapter or get_adapter()
        self.actor_user_id = actor_user_id

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_session:
            try:
                self.db.commit()
            finally:
                self.db.close()

    @staticmethod
    def _require_admin(db_session: Session, actor_user_id: int | None) -> None:
        """Enforce admin-only operations in the service layer, not just routes."""

        if actor_user_id is None:
            raise PreventionError("an authenticated actor is required")
        actor = db_session.get(User, actor_user_id)
        if actor is None or actor.role != UserRole.ADMIN or not actor.is_active:
            raise PreventionError("administrator permission required")

    def _record_action(
        self,
        *,
        action: PreventionActionType,
        ip: str,
        result: CommandResult | None,
        rule_name: str | None = None,
        block_id: int | None = None,
        decision_id: int | None = None,
        actor_user_id: int | None = None,
        result_override: str | None = None,
        error: str | None = None,
    ) -> PreventionAction:
        row = PreventionAction(
            block_id=block_id,
            decision_id=decision_id,
            action=action.value,
            ip_address=ip,
            rule_name=rule_name,
            dry_run=bool(result and result.dry_run),
            command_preview=None if result is None else result.preview,
            result=result_override or (result.result_label if result else "NOOP"),
            error=error[:500] if error else None,
            actor_user_id=actor_user_id,
            correlation_id=get_correlation_id(),
        )
        self.db.add(row)
        self.db.flush()
        return row

    def _notify_failure(self, title: str, detail: str) -> None:
        """Create an in-app alert for a failed or drifting firewall operation."""

        from utils.alerts import create_operational_notification

        create_operational_notification(
            title=title,
            message=detail,
            severity="high",
            db_session=self.db,
        )

    def _audit(self, action: str, resource_id: str, **details: Any) -> None:
        log_security_event(
            action=action,
            resource_type="FIREWALL",
            resource_id=resource_id,
            user_id=self.actor_user_id,
            status="SUCCESS",
            details=audit_details(**details),
            db_session=self.db,
        )

    def block_ip(
        self,
        ip: str,
        *,
        reason: str,
        duration_minutes: int | None = None,
        decision_id: int | None = None,
        requires_approval: bool = False,
        manual: bool = False,
        actor_user_id: int | None = None,
        admin_ip: str | None = None,
    ) -> BlockedIP:
        """Create a temporary block (or pending approval) after safety checks."""

        address = parse_ip(ip)
        normalized = str(address)
        actor = actor_user_id if actor_user_id is not None else self.actor_user_id
        if manual:
            self._require_admin(self.db, actor)

        from prevention.policy import build_context

        context = build_context(self.db, admin_ip=admin_ip)
        if is_whitelisted_ip(normalized, context) or is_protected_ip(
            normalized, context
        ):
            raise ProtectedTargetError("address is protected from blocking")
        if not manual and settings.PREVENTION_KILL_SWITCH:
            raise PreventionError("automated blocking is disabled by kill switch")

        existing = (
            self.db.execute(
                select(BlockedIP).where(
                    BlockedIP.ip_address == normalized,
                    BlockedIP.status.in_(
                        [BlockStatus.ACTIVE, BlockStatus.PENDING_APPROVAL]
                    ),
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            return existing

        duration = duration_minutes or settings.PREVENTION_BLOCK_DURATION_MINUTES
        if duration <= 0:
            raise PreventionError("block duration must be positive")
        rule_name = self.adapter.rule_name(normalized)
        now = datetime.now(UTC)

        if requires_approval:
            row = BlockedIP(
                ip_address=normalized,
                reason=reason[:255],
                status=BlockStatus.PENDING_APPROVAL,
                escalation_level=1,
                blocked_at=now,
                expires_at=now + timedelta(minutes=duration),
                is_dry_run=True,
                firewall_rule_name=rule_name,
                created_by_user_id=actor,
            )
            self.db.add(row)
            self.db.flush()
            self._record_action(
                action=PreventionActionType.BLOCK,
                ip=normalized,
                result=None,
                rule_name=rule_name,
                block_id=row.id,
                decision_id=decision_id,
                actor_user_id=actor,
                result_override="PENDING",
            )
            self._audit(
                "FIREWALL_BLOCK_PENDING_APPROVAL",
                str(row.id),
                ip=normalized,
                rule_name=rule_name,
            )
            return row

        result = self.adapter.block(normalized, duration)
        if not result.success:
            self._record_action(
                action=PreventionActionType.BLOCK,
                ip=normalized,
                result=result,
                rule_name=rule_name,
                decision_id=decision_id,
                actor_user_id=actor,
                error=result.stderr or "firewall command failed",
            )
            self._notify_failure(
                "Firewall block failed",
                f"Block command for a flagged source failed: {result.stderr or 'unknown error'}",
            )
            raise FirewallActionError(result.stderr or "firewall command failed")

        row = BlockedIP(
            ip_address=normalized,
            reason=reason[:255],
            status=BlockStatus.ACTIVE,
            escalation_level=1,
            blocked_at=now,
            expires_at=now + timedelta(minutes=duration),
            is_dry_run=result.dry_run,
            firewall_rule_name=rule_name,
            created_by_user_id=actor,
            approved_by_user_id=actor if manual else None,
        )
        self.db.add(row)
        self.db.flush()
        self._record_action(
            action=PreventionActionType.BLOCK,
            ip=normalized,
            result=result,
            rule_name=rule_name,
            block_id=row.id,
            decision_id=decision_id,
            actor_user_id=actor,
        )
        self._audit(
            "FIREWALL_BLOCK_APPLIED",
            str(row.id),
            ip=normalized,
            dry_run=result.dry_run,
            rule_name=rule_name,
        )
        return row

    def approve_block(
        self, block_id: int, *, actor_user_id: int | None = None
    ) -> BlockedIP:
        """Apply a pending block after explicit administrator approval."""

        actor = actor_user_id or self.actor_user_id
        self._require_admin(self.db, actor)
        block = self.db.get(BlockedIP, block_id)
        if block is None or block.status != BlockStatus.PENDING_APPROVAL:
            raise PreventionError("block is not pending approval")
        result = self.adapter.block(block.ip_address, self._remaining_minutes(block))
        if not result.success:
            self._record_action(
                action=PreventionActionType.BLOCK,
                ip=block.ip_address,
                result=result,
                rule_name=block.firewall_rule_name,
                block_id=block.id,
                actor_user_id=actor,
                error=result.stderr or "firewall command failed",
            )
            self._notify_failure(
                "Approved firewall block failed",
                f"Approved block command failed: {result.stderr or 'unknown error'}",
            )
            raise FirewallActionError(result.stderr or "firewall command failed")
        block.status = BlockStatus.ACTIVE
        block.blocked_at = datetime.now(UTC)
        block.is_dry_run = result.dry_run
        block.approved_by_user_id = actor
        self._record_action(
            action=PreventionActionType.BLOCK,
            ip=block.ip_address,
            result=result,
            rule_name=block.firewall_rule_name,
            block_id=block.id,
            actor_user_id=actor,
        )
        self._audit(
            "FIREWALL_BLOCK_APPROVED",
            str(block.id),
            ip=block.ip_address,
            dry_run=result.dry_run,
        )
        return block

    def reject_block(
        self, block_id: int, *, actor_user_id: int | None = None
    ) -> BlockedIP:
        """Reject a pending approval without touching firewall state."""

        actor = actor_user_id or self.actor_user_id
        self._require_admin(self.db, actor)
        block = self.db.get(BlockedIP, block_id)
        if block is None or block.status != BlockStatus.PENDING_APPROVAL:
            raise PreventionError("block is not pending approval")
        block.status = BlockStatus.RELEASED
        block.released_at = datetime.now(UTC)
        block.released_by_user_id = actor
        block.release_reason = "approval rejected"
        self._audit(
            "FIREWALL_BLOCK_APPROVAL_REJECTED", str(block.id), ip=block.ip_address
        )
        return block

    def unblock_ip(
        self,
        ip: str,
        *,
        reason: str,
        manual: bool = False,
        actor_user_id: int | None = None,
    ) -> list[BlockedIP]:
        """Remove all active blocks for one address."""

        address = parse_ip(ip)
        normalized = str(address)
        actor = actor_user_id or self.actor_user_id
        if manual:
            self._require_admin(self.db, actor)
        blocks = (
            self.db.execute(
                select(BlockedIP).where(
                    BlockedIP.ip_address == normalized,
                    BlockedIP.status.in_(
                        [BlockStatus.ACTIVE, BlockStatus.PENDING_APPROVAL]
                    ),
                )
            )
            .scalars()
            .all()
        )
        released: list[BlockedIP] = []
        for block in blocks:
            if block.status == BlockStatus.ACTIVE:
                result = self.adapter.unblock(normalized)
                if not result.success:
                    self._record_action(
                        action=PreventionActionType.UNBLOCK,
                        ip=normalized,
                        result=result,
                        rule_name=block.firewall_rule_name,
                        block_id=block.id,
                        actor_user_id=actor,
                        error=result.stderr or "firewall command failed",
                    )
                    self._notify_failure(
                        "Firewall unblock failed",
                        f"Unblock command for a released address failed: {result.stderr or 'unknown error'}",
                    )
                    raise FirewallActionError(
                        result.stderr or "firewall command failed"
                    )
            else:
                result = None
            block.status = BlockStatus.RELEASED
            block.released_at = datetime.now(UTC)
            block.released_by_user_id = actor
            block.release_reason = reason[:255]
            self._record_action(
                action=PreventionActionType.UNBLOCK,
                ip=normalized,
                result=result,
                rule_name=block.firewall_rule_name,
                block_id=block.id,
                actor_user_id=actor,
                result_override="PENDING_RELEASED" if result is None else None,
            )
            self._audit(
                "FIREWALL_UNBLOCK_APPLIED",
                str(block.id),
                ip=normalized,
                dry_run=bool(result and result.dry_run),
                reason=reason,
            )
            released.append(block)
        return released

    def extend_block(
        self,
        block_id: int,
        *,
        additional_minutes: int,
        actor_user_id: int | None = None,
    ) -> BlockedIP:
        """Extend a temporary block with an idempotent adapter re-apply."""

        actor = actor_user_id or self.actor_user_id
        self._require_admin(self.db, actor)
        if additional_minutes <= 0:
            raise PreventionError("extension must be positive")
        block = self.db.get(BlockedIP, block_id)
        if block is None or block.status != BlockStatus.ACTIVE:
            raise PreventionError("block is not active")
        new_duration = self._remaining_minutes(block) + additional_minutes
        result = self.adapter.block(block.ip_address, new_duration)
        if not result.success:
            self._record_action(
                action=PreventionActionType.EXTEND,
                ip=block.ip_address,
                result=result,
                rule_name=block.firewall_rule_name,
                block_id=block.id,
                actor_user_id=actor,
                error=result.stderr or "firewall command failed",
            )
            raise FirewallActionError(result.stderr or "firewall command failed")
        block.expires_at = _as_utc(block.expires_at) + timedelta(
            minutes=additional_minutes
        )
        self._record_action(
            action=PreventionActionType.EXTEND,
            ip=block.ip_address,
            result=result,
            rule_name=block.firewall_rule_name,
            block_id=block.id,
            actor_user_id=actor,
        )
        self._audit(
            "FIREWALL_BLOCK_EXTENDED",
            str(block.id),
            ip=block.ip_address,
            additional_minutes=additional_minutes,
        )
        return block

    def add_whitelist(
        self, cidr: str, description: str, *, actor_user_id: int | None = None
    ) -> Whitelist:
        """Add a validated non-immutable CIDR to the protected allowlist."""

        actor = actor_user_id or self.actor_user_id
        self._require_admin(self.db, actor)
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise PreventionError("invalid CIDR") from exc
        if network.prefixlen == 0:
            raise PreventionError("a /0 allowlist entry is not permitted")
        normalized = str(network)
        existing = (
            self.db.execute(select(Whitelist).where(Whitelist.cidr == normalized))
            .scalars()
            .first()
        )
        if existing is not None:
            return existing
        row = Whitelist(
            cidr=normalized,
            description=description[:255],
            is_immutable=False,
            created_by_user_id=actor,
        )
        self.db.add(row)
        self.db.flush()
        self._audit(
            "FIREWALL_WHITELIST_ADDED",
            str(row.id),
            cidr=normalized,
            description=description[:255],
        )
        return row

    @staticmethod
    def _remaining_minutes(block: BlockedIP) -> int:
        remaining = _as_utc(block.expires_at) - datetime.now(UTC)
        return max(1, int(remaining.total_seconds() // 60))

    def expire_due_blocks(
        self, *, adapter: FirewallAdapter | None = None
    ) -> dict[str, int]:
        """Roll back every expired block; failures leave the block active."""

        active_adapter = adapter or self.adapter
        now = datetime.now(UTC)
        due = (
            self.db.execute(
                select(BlockedIP).where(
                    BlockedIP.status == BlockStatus.ACTIVE,
                    BlockedIP.expires_at <= now,
                )
            )
            .scalars()
            .all()
        )
        report = {"expired": 0, "failed": 0}
        for block in due:
            result = active_adapter.unblock(block.ip_address)
            if not result.success:
                report["failed"] += 1
                self._record_action(
                    action=PreventionActionType.UNBLOCK,
                    ip=block.ip_address,
                    result=result,
                    rule_name=block.firewall_rule_name,
                    block_id=block.id,
                    error=result.stderr or "expiry rollback failed",
                )
                self._notify_failure(
                    "Firewall expiry rollback failed",
                    f"Could not remove an expired rule: {result.stderr or 'unknown error'}",
                )
                continue
            block.status = BlockStatus.EXPIRED
            block.released_at = now
            block.release_reason = "expired"
            self._record_action(
                action=PreventionActionType.UNBLOCK,
                ip=block.ip_address,
                result=result,
                rule_name=block.firewall_rule_name,
                block_id=block.id,
            )
            report["expired"] += 1
        if due:
            self._audit("FIREWALL_EXPIRY_PROCESSED", "bulk", **report)
        return report

    def reconcile(self, *, adapter: FirewallAdapter | None = None) -> dict[str, Any]:
        """Compare database state with observed rules and report drift."""

        active_adapter = adapter or self.adapter
        expected = {
            block.firewall_rule_name or self.adapter.rule_name(block.ip_address)
            for block in self.db.execute(
                select(BlockedIP).where(BlockedIP.status == BlockStatus.ACTIVE)
            )
            .scalars()
            .all()
        }
        actual = set(active_adapter.list_rules())
        drift = {
            "missing_rules": sorted(expected - actual),
            "unexpected_rules": sorted(
                rule for rule in actual - expected if rule.startswith(RULE_PREFIX)
            ),
            "mode": (
                "dry-run"
                if getattr(active_adapter, "dry_run", False)
                or isinstance(active_adapter, DryRunAdapter)
                else "active"
            ),
        }
        preview = json.dumps(active_adapter.build_list_command())
        result = CommandResult(
            success=True,
            dry_run=drift["mode"] == "dry-run",
            preview=preview,
        )
        self._record_action(
            action=PreventionActionType.RECONCILE,
            ip="192.0.2.0",  # TEST-NET placeholder for a bulk reconcile action
            result=result,
        )
        if drift["missing_rules"] or drift["unexpected_rules"]:
            self._notify_failure(
                "Firewall rule drift detected",
                "Managed firewall rules differ from the database state.",
            )
            self._audit(
                "FIREWALL_RECONCILIATION_DRIFT",
                "bulk",
                missing_rules=drift["missing_rules"],
                unexpected_rules=drift["unexpected_rules"],
            )
        return drift

"""Policy evaluation for automated prevention decisions.

The engine enforces a conservative decision order: protected/whitelisted
addresses are never blocked, rare/low-support classes remain alert-only, a
single prediction can never produce a block, and every outcome is persisted.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from core.logging import get_logger
from core.models.prevention import (
    DecisionAction,
    PolicyConfig,
    PreventionCandidate,
    PreventionDecision,
    Whitelist,
)
from core.security import audit_details, log_security_event

logger = get_logger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_SEVERITY_MAPPING: dict[str, str] = {
    "Heartbleed": "critical",
    "Infiltration": "critical",
    "SQL Injection": "high",
    "Web Attack - Sql Injection": "high",
    "Bot": "high",
    "DDoS": "high",
    "DoS GoldenEye": "high",
    "DoS Hulk": "high",
    "DoS Slowhttptest": "medium",
    "PortScan": "medium",
    "FTP-Patator": "medium",
    "SSH-Patator": "medium",
}
DEFAULT_CLASS_ACTIONS: dict[str, str] = {
    "Heartbleed": "alert_only",
    "Infiltration": "alert_only",
    "SQL Injection": "alert_only",
    "Web Attack - Sql Injection": "alert_only",
}

_VALID_ACTIONS = {"block", "alert_only", "no_action"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _parse_csv(value: str | None) -> tuple[str, ...]:
    """Parse a comma-separated setting into normalized non-empty strings."""

    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _parse_networks(values: tuple[str, ...]) -> tuple[IPNetwork, ...]:
    """Validate CIDR/IP strings, dropping malformed operator input."""

    networks: list[IPNetwork] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid protected CIDR entry")
    return tuple(networks)


class PolicySettings(BaseModel):
    """Validated, runtime-editable policy values."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    confidence_threshold: float = Field(default=0.85, ge=0.5, le=1.0)
    min_detections: int = Field(default=2, ge=2)
    window_seconds: int = Field(default=60, gt=0)
    severity_mapping: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_MAPPING)
    )
    class_actions: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_CLASS_ACTIONS)
    )
    block_duration_minutes: int = Field(default=15, gt=0)
    escalation_ladder_minutes: list[int] = Field(
        default_factory=lambda: [15, 60, 240, 1440]
    )
    approval_mode: bool = False
    kill_switch: bool = False
    rare_classes: set[str] = Field(
        default_factory=lambda: set(_parse_csv(settings.PREVENTION_RARE_CLASSES))
    )

    @field_validator("severity_mapping")
    @classmethod
    def validate_severities(cls, value: dict[str, str]) -> dict[str, str]:
        for label, severity in value.items():
            if not label.strip() or severity not in _VALID_SEVERITIES:
                raise ValueError("invalid severity mapping")
        return value

    @field_validator("class_actions")
    @classmethod
    def validate_class_actions(cls, value: dict[str, str]) -> dict[str, str]:
        for label, action in value.items():
            if not label.strip() or action not in _VALID_ACTIONS:
                raise ValueError("invalid class action")
        return value

    @field_validator("escalation_ladder_minutes")
    @classmethod
    def validate_ladder(cls, value: list[int]) -> list[int]:
        if not value or any(minutes <= 0 for minutes in value):
            raise ValueError("escalation ladder must contain positive durations")
        return value

    @model_validator(mode="after")
    def ensure_sorted_ladder(self) -> PolicySettings:
        self.escalation_ladder_minutes = sorted(set(self.escalation_ladder_minutes))
        return self

    @classmethod
    def from_config(cls, payload: str | None = None) -> PolicySettings:
        """Load defaults, apply stored overrides, then apply kill-switch."""

        defaults = cls(
            confidence_threshold=settings.PREVENTION_CONFIDENCE_THRESHOLD,
            min_detections=settings.PREVENTION_MIN_DETECTIONS,
            window_seconds=settings.PREVENTION_WINDOW_SECONDS,
            block_duration_minutes=settings.PREVENTION_BLOCK_DURATION_MINUTES,
            escalation_ladder_minutes=[
                int(value)
                for value in _parse_csv(settings.PREVENTION_ESCALATION_LADDER_MINUTES)
            ]
            or [settings.PREVENTION_BLOCK_DURATION_MINUTES],
            approval_mode=settings.PREVENTION_REQUIRE_APPROVAL,
        ).model_dump()
        overrides: dict[str, Any] = {}
        if payload:
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValueError("policy configuration is not valid JSON") from exc
            if not isinstance(parsed, dict):
                raise ValueError("policy configuration must be a JSON object")
            overrides = parsed
        merged = {**defaults, **overrides}
        merged["kill_switch"] = bool(
            settings.PREVENTION_KILL_SWITCH or merged.get("kill_switch", False)
        )
        return cls.model_validate(merged)


@dataclass(frozen=True)
class DecisionContext:
    """Inputs used to protect infrastructure during a policy evaluation."""

    db_session: Session
    now: datetime
    admin_ip: IPAddress | None
    local_ips: frozenset[IPAddress]
    gateway_ips: frozenset[IPAddress]
    dns_ips: frozenset[IPAddress]
    protected_networks: tuple[IPNetwork, ...]
    whitelist_networks: tuple[IPNetwork, ...]

    @property
    def protected_addresses(self) -> frozenset[IPAddress]:
        return (
            self.local_ips
            | self.gateway_ips
            | self.dns_ips
            | ({self.admin_ip} if self.admin_ip else frozenset())
        )


@dataclass(frozen=True)
class PolicyDecision:
    """Persisted outcome of one candidate evaluation."""

    action: DecisionAction
    reason: str
    severity: str
    repeat_count: int
    escalation_level: int
    block_duration_minutes: int | None = None
    requires_approval: bool = False
    kill_switch_active: bool = False
    details: dict[str, Any] = field(default_factory=dict)


def _addresses(values: tuple[str, ...]) -> frozenset[IPAddress]:
    resolved: set[IPAddress] = set()
    for value in values:
        try:
            candidate = ipaddress.ip_address(value)
        except ValueError:
            try:
                network = ipaddress.ip_network(value, strict=False)
                resolved.add(network.network_address)
            except ValueError:
                logger.warning("Ignoring invalid protected address entry")
                continue
        else:
            resolved.add(candidate)
    return frozenset(resolved)


def _local_addresses() -> frozenset[IPAddress]:
    """Discover the server's own IPs without invoking any shell command."""

    resolved: set[IPAddress] = set()
    try:
        import psutil  # local import: optional on minimal deployments

        for addresses in psutil.net_if_addrs().values():
            for entry in addresses:
                try:
                    resolved.add(ipaddress.ip_address(str(entry.address).split("%")[0]))
                except ValueError:
                    continue
    except Exception:  # noqa: BLE001 - discovery is best-effort by design
        logger.warning(
            "Could not enumerate local interfaces; using configured protections"
        )
    return frozenset(resolved)


def _resolv_conf_servers() -> tuple[str, ...]:
    """Read DNS servers from resolv.conf where available (no subprocess)."""

    path = Path("/etc/resolv.conf")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()
    servers: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("nameserver "):
            parts = stripped.split()
            if len(parts) >= 2:
                servers.append(parts[1])
    return tuple(servers)


def build_context(
    db_session: Session,
    *,
    admin_ip: str | None = None,
    now: datetime | None = None,
) -> DecisionContext:
    """Build a protection context from configuration and database state."""

    configured_admin = admin_ip or getattr(settings, "PREVENTION_ADMIN_IP", None)
    admin_address: IPAddress | None = None
    if configured_admin:
        try:
            admin_address = ipaddress.ip_address(configured_admin)
        except ValueError:
            logger.warning("Ignoring invalid configured admin IP")

    whitelist = list(settings.get_parsed_whitelist())
    for row in db_session.execute(select(Whitelist)).scalars().all():
        try:
            whitelist.append(ipaddress.ip_network(row.cidr, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid whitelist row")

    dns_values = _parse_csv(settings.PREVENTION_DNS_SERVERS) + _resolv_conf_servers()
    return DecisionContext(
        db_session=db_session,
        now=now or datetime.now(UTC),
        admin_ip=admin_address,
        local_ips=_local_addresses(),
        gateway_ips=_addresses(_parse_csv(settings.PREVENTION_DEFAULT_GATEWAYS)),
        dns_ips=_addresses(dns_values),
        protected_networks=_parse_networks(
            _parse_csv(settings.PREVENTION_PROTECTED_CIDRS)
        ),
        whitelist_networks=tuple(whitelist),
    )


def parse_ip(value: str) -> IPAddress:
    """Strictly parse one IP address; injection strings are always rejected."""

    if not isinstance(value, str) or value != value.strip():
        raise ValueError("IP address must be a trimmed string")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc


def is_protected_ip(ip: str, context: DecisionContext) -> bool:
    """Return True when an address must never be blocked."""

    try:
        address = parse_ip(ip)
    except ValueError:
        return True

    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    ):
        return True
    if address in context.protected_addresses:
        return True
    return any(
        address.version == network.version and address in network
        for network in context.protected_networks
    )


def is_whitelisted_ip(ip: str, context: DecisionContext) -> bool:
    """Return True when an address is explicitly protected from blocking."""

    try:
        address = parse_ip(ip)
    except ValueError:
        return True
    return any(
        address.version == network.version and address in network
        for network in context.whitelist_networks
    )


def get_or_create_policy(
    db_session: Session, *, actor_user_id: int | None = None
) -> PolicyConfig:
    """Return the active policy, creating the safe default when absent."""

    config = (
        db_session.execute(select(PolicyConfig).where(PolicyConfig.is_active.is_(True)))
        .scalars()
        .first()
    )
    if config is not None:
        return config

    config = PolicyConfig(
        name="default",
        is_active=True,
        version="phase6-default",
        config_json=json.dumps(
            PolicySettings.from_config().model_dump(mode="json"), sort_keys=True
        ),
        updated_by_user_id=actor_user_id,
    )
    db_session.add(config)
    db_session.flush()
    return config


def persist_candidate(
    db_session: Session,
    candidate: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
) -> PreventionCandidate:
    """Store one candidate event; duplicate event IDs are a no-op."""

    candidate_id = str(candidate["candidate_id"])
    existing = (
        db_session.execute(
            select(PreventionCandidate).where(
                PreventionCandidate.candidate_id == candidate_id
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing

    row = PreventionCandidate(
        event_id=str(candidate["event_id"]),
        candidate_id=candidate_id,
        detection_event_id=str(candidate["detection_event_id"]),
        detection_id=(
            int(candidate["detection_id"]) if candidate.get("detection_id") else None
        ),
        flow_id=str(candidate["flow_id"]),
        src_ip=str(candidate["src_ip"]),
        dst_ip=str(candidate["dst_ip"]),
        dst_port=int(candidate["dst_port"]),
        model_version=str(candidate["model_version"]),
        predicted_label=str(candidate["predicted_label"]),
        verdict=str(candidate["verdict"]),
        confidence=float(candidate["confidence_score"]),
        rare_class_flag=bool(candidate.get("rare_class_flag", False)),
        simulation=bool(candidate.get("simulation", True)),
        source_label=candidate.get("source_label"),
        observed_at=observed_at or datetime.now(UTC),
    )
    db_session.add(row)
    db_session.flush()
    return row


def count_recent_candidates(
    db_session: Session,
    *,
    src_ip: str,
    predicted_label: str,
    window_seconds: int,
    now: datetime,
    exclude_candidate_id: str | None = None,
) -> int:
    """Count prior candidates in the repeat-detection window."""

    statement = select(PreventionCandidate).where(
        PreventionCandidate.src_ip == src_ip,
        PreventionCandidate.predicted_label == predicted_label,
        PreventionCandidate.observed_at >= now - timedelta(seconds=window_seconds),
    )
    if exclude_candidate_id:
        statement = statement.where(
            PreventionCandidate.candidate_id != exclude_candidate_id
        )
    return len(db_session.execute(statement).scalars().all())


def evaluate(
    candidate: Mapping[str, Any],
    *,
    policy: PolicySettings,
    context: DecisionContext,
    repeat_count: int,
) -> PolicyDecision:
    """Evaluate one candidate using the documented decision order."""

    src_ip = str(candidate["src_ip"])
    label = str(candidate["predicted_label"])
    confidence = float(candidate["confidence_score"])
    verdict = str(candidate["verdict"])
    rare = bool(candidate.get("rare_class_flag", False)) or label in policy.rare_classes
    severity = policy.severity_mapping.get(label, "medium")
    details: dict[str, Any] = {
        "predicted_label": label,
        "confidence_score": confidence,
        "verdict": verdict,
        "rare_class": rare,
        "repeat_count": repeat_count,
    }

    if is_whitelisted_ip(src_ip, context):
        return PolicyDecision(
            action=DecisionAction.NO_ACTION,
            reason="whitelisted_address",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )
    if is_protected_ip(src_ip, context):
        return PolicyDecision(
            action=DecisionAction.NO_ACTION,
            reason="protected_address",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )
    if rare:
        return PolicyDecision(
            action=DecisionAction.ALERT_ONLY,
            reason="rare_or_low_support_class_alert_only",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )
    if confidence < policy.confidence_threshold or verdict != "known attack":
        return PolicyDecision(
            action=DecisionAction.NO_ACTION,
            reason="confidence_or_verdict_below_threshold",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )

    class_action = policy.class_actions.get(label, "block")
    if class_action == "no_action":
        return PolicyDecision(
            action=DecisionAction.NO_ACTION,
            reason="class_action_no_action",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )
    if class_action == "alert_only":
        return PolicyDecision(
            action=DecisionAction.ALERT_ONLY,
            reason="class_action_alert_only",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )
    if repeat_count < policy.min_detections:
        return PolicyDecision(
            action=DecisionAction.NO_ACTION,
            reason="single_or_insufficient_repeat_detections",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=0,
            details=details,
        )

    ladder = policy.escalation_ladder_minutes
    escalation_level = min(repeat_count - policy.min_detections, len(ladder) - 1)
    duration = ladder[escalation_level]

    if policy.kill_switch:
        return PolicyDecision(
            action=DecisionAction.ALERT_ONLY,
            reason="automated_blocking_kill_switch_active",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=escalation_level,
            block_duration_minutes=duration,
            kill_switch_active=True,
            details=details,
        )
    if policy.approval_mode:
        return PolicyDecision(
            action=DecisionAction.PENDING_APPROVAL,
            reason="human_approval_required",
            severity=severity,
            repeat_count=repeat_count,
            escalation_level=escalation_level,
            block_duration_minutes=duration,
            requires_approval=True,
            details=details,
        )
    return PolicyDecision(
        action=DecisionAction.BLOCK,
        reason="repeat_high_confidence_detections",
        severity=severity,
        repeat_count=repeat_count,
        escalation_level=escalation_level,
        block_duration_minutes=duration,
        details=details,
    )


def record_decision(
    db_session: Session,
    decision: PolicyDecision,
    *,
    candidate: Mapping[str, Any] | None = None,
    actor_user_id: int | None = None,
    block_id: int | None = None,
    audit: bool = True,
) -> PreventionDecision:
    """Persist a decision and audit privileged outcomes."""

    row = PreventionDecision(
        candidate_id=None if candidate is None else str(candidate.get("candidate_id")),
        src_ip=str(candidate.get("src_ip")) if candidate else "unknown",
        predicted_label=(
            str(candidate.get("predicted_label")) if candidate else "unknown"
        ),
        action=decision.action.value,
        reason=decision.reason[:500],
        severity=decision.severity,
        block_duration_minutes=decision.block_duration_minutes,
        requires_approval=decision.requires_approval,
        kill_switch_active=decision.kill_switch_active,
        repeat_count=decision.repeat_count,
        escalation_level=decision.escalation_level,
        details_json=json.dumps(decision.details, sort_keys=True, default=str),
        block_id=block_id,
        actor_user_id=actor_user_id,
    )
    db_session.add(row)
    db_session.flush()

    if audit and decision.action in {
        DecisionAction.BLOCK,
        DecisionAction.PENDING_APPROVAL,
    }:
        log_security_event(
            action=f"PREVENTION_{decision.action.value.upper()}",
            resource_type="PREVENTION_DECISION",
            resource_id=str(row.id),
            user_id=actor_user_id,
            status="SUCCESS",
            details=audit_details(
                candidate_id=row.candidate_id,
                src_ip=row.src_ip,
                severity=row.severity,
                reason=row.reason,
                block_duration_minutes=row.block_duration_minutes,
            ),
            db_session=db_session,
        )
    return row

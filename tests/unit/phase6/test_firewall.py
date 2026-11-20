"""Firewall adapter safety tests. No real firewall command is ever executed."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from core.config import settings
from core.models.prevention import (
    BlockStatus,
    PreventionAction,
    PreventionActionType,
    Whitelist,
)
from core.models.user import UserRole
from prevention.firewall_linux import LinuxFirewallAdapter
from prevention.firewall_windows import WindowsFirewallAdapter
from prevention.ip_blocker import (
    BlockManager,
    CommandResult,
    DryRunAdapter,
    execute_firewall_command,
    get_adapter,
    real_enforcement_enabled,
)
from prevention.policy import parse_ip

DUMMY_IP = "45.33.32.156"


@pytest.fixture(autouse=True)
def _no_local_ips(monkeypatch):
    """Make protection checks deterministic on any host."""

    monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())


@pytest.fixture
def admin_id(make_user):
    return make_user("fw_admin", role=UserRole.ADMIN)


class TestCommandBuilders:
    @pytest.mark.parametrize(
        "adapter_cls", [WindowsFirewallAdapter, LinuxFirewallAdapter]
    )
    def test_ip_is_validated_and_command_is_argv_list(self, adapter_cls):
        adapter = adapter_cls()
        rule = adapter.rule_name(DUMMY_IP)
        block_cmd = adapter.build_block_command(DUMMY_IP, rule)
        unblock_cmd = adapter.build_unblock_command(DUMMY_IP, rule)
        list_cmd = adapter.build_list_command()

        for command in (block_cmd, unblock_cmd, list_cmd):
            assert isinstance(command, list)
            assert all(isinstance(argument, str) for argument in command)
            assert all(
                ";" not in argument and "|" not in argument for argument in command
            )

        # Block commands carry the validated address; unblock/list commands
        # identify managed rules by their stable prefixed rule name instead.
        assert DUMMY_IP in " ".join(block_cmd)
        assert rule in " ".join(unblock_cmd)

    def test_shell_metacharacters_are_rejected_by_ip_validation(self):
        with pytest.raises(ValueError):
            parse_ip("1.2.3.4; rm -rf /")
        with pytest.raises(ValueError):
            parse_ip("1.2.3.4 && netsh firewall set opmode disable")
        with pytest.raises(ValueError):
            parse_ip("$(whoami)")

    def test_rule_names_are_stable_prefixed_and_safe(self):
        adapter = WindowsFirewallAdapter()
        first = adapter.rule_name(DUMMY_IP)
        assert first == adapter.rule_name(DUMMY_IP)
        assert first.startswith("AI-IDS-")
        assert len(first) == len("AI-IDS-") + 12
        assert all(character.isalnum() or character == "-" for character in first)

    def test_linux_uses_ip6tables_for_ipv6(self):
        adapter = LinuxFirewallAdapter()
        command = adapter.build_block_command(
            "2001:db8::10", adapter.rule_name("2001:db8::10")
        )
        assert command[0] == "ip6tables"


class TestSafetyGate:
    def test_default_mode_is_dry_run(self):
        assert settings.PREVENTION_MODE == "dry_run"
        assert isinstance(get_adapter(), DryRunAdapter)
        assert real_enforcement_enabled() is False

    def test_simulation_mode_forces_dry_run_even_with_active_settings(
        self, monkeypatch
    ):
        monkeypatch.setattr(settings, "PREVENTION_MODE", "active")
        monkeypatch.setattr(settings, "PREVENTION_ALLOW_REAL_ENFORCEMENT", True)
        monkeypatch.setattr(settings, "CAPTURE_MODE", "simulation")
        assert real_enforcement_enabled() is False
        assert isinstance(get_adapter(), DryRunAdapter)

    def test_execute_refuses_when_not_explicitly_enabled(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            "prevention.ip_blocker.subprocess.run",
            lambda *args, **kwargs: called.append((args, kwargs)),
        )
        result = execute_firewall_command(["netsh", "advfirewall", "show", "all"])
        assert result.success is False
        assert result.dry_run is True
        assert "disabled" in (result.error or "")
        assert called == []

    def test_execute_with_mock_uses_argv_list_and_shell_false(self, monkeypatch):
        monkeypatch.setattr(settings, "PREVENTION_MODE", "active")
        monkeypatch.setattr(settings, "PREVENTION_ALLOW_REAL_ENFORCEMENT", True)
        monkeypatch.setattr(settings, "CAPTURE_MODE", "live")

        calls: list[tuple[list[str], dict[str, object]]] = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("prevention.ip_blocker.subprocess.run", fake_run)
        assert real_enforcement_enabled() is True

        adapter = WindowsFirewallAdapter()
        rule = adapter.rule_name(DUMMY_IP)
        result = adapter.block(DUMMY_IP, 15)

        assert result.success is True
        assert result.dry_run is False
        assert len(calls) == 1
        command, kwargs = calls[0]
        assert command[0] == "netsh"
        assert command == adapter.build_block_command(DUMMY_IP, rule)
        assert kwargs["shell"] is False
        assert kwargs["check"] is False
        assert json.loads(result.preview) == command


class TestDryRunAdapter:
    def test_dry_run_never_calls_delegate_execution(self):
        class ExplodingAdapter(WindowsFirewallAdapter):
            def block(self, ip, duration_minutes):
                pytest.fail("dry-run must not execute block")

            def unblock(self, ip):
                pytest.fail("dry-run must not execute unblock")

        adapter = DryRunAdapter(ExplodingAdapter())
        blocked = adapter.block(DUMMY_IP, 15)
        unblocked = adapter.unblock(DUMMY_IP)
        assert blocked.dry_run is True and blocked.result_label == "SIMULATED"
        assert unblocked.dry_run is True and unblocked.result_label == "SIMULATED"
        assert json.loads(blocked.preview)[0] == "netsh"

    def test_block_manager_records_simulated_actions(self, db_session, admin_id):
        manager = BlockManager(
            db_session, DryRunAdapter(WindowsFirewallAdapter()), actor_user_id=admin_id
        )
        block = manager.block_ip(DUMMY_IP, reason="test block", manual=True)
        assert block.status == BlockStatus.ACTIVE
        assert block.is_dry_run is True
        assert block.firewall_rule_name.startswith("AI-IDS-")

        actions = (
            db_session.execute(
                select(PreventionAction).where(PreventionAction.block_id == block.id)
            )
            .scalars()
            .all()
        )
        assert len(actions) == 1
        assert actions[0].action == PreventionActionType.BLOCK.value
        assert actions[0].result == "SIMULATED"
        assert actions[0].dry_run is True
        assert json.loads(actions[0].command_preview or "[]")[0] == "netsh"

    def test_manual_block_requires_admin(self, db_session, make_user):
        viewer_id = make_user("fw_viewer", role=UserRole.VIEWER)
        manager = BlockManager(
            db_session, DryRunAdapter(WindowsFirewallAdapter()), actor_user_id=viewer_id
        )
        with pytest.raises(RuntimeError, match="administrator"):
            manager.block_ip(DUMMY_IP, reason="denied", manual=True)

    def test_protected_and_whitelisted_addresses_are_refused(
        self, db_session, admin_id, monkeypatch
    ):
        manager = BlockManager(
            db_session, DryRunAdapter(WindowsFirewallAdapter()), actor_user_id=admin_id
        )
        with pytest.raises(RuntimeError, match="protected"):
            manager.block_ip("127.0.0.1", reason="loopback", manual=True)

        db_session.add(
            Whitelist(
                cidr=f"{DUMMY_IP}/32", description="allowlisted", is_immutable=False
            )
        )
        db_session.flush()
        with pytest.raises(RuntimeError, match="protected"):
            manager.block_ip(DUMMY_IP, reason="allowlisted", manual=True)

    def test_unblock_and_expiry_release_rules(self, db_session, admin_id):
        manager = BlockManager(
            db_session, DryRunAdapter(WindowsFirewallAdapter()), actor_user_id=admin_id
        )
        manager.block_ip(DUMMY_IP, reason="test", manual=True)
        released = manager.unblock_ip(DUMMY_IP, reason="manual release", manual=True)
        assert released[0].status == BlockStatus.RELEASED

        block2 = manager.block_ip("45.33.32.157", reason="expiring", manual=True)
        block2.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db_session.flush()
        report = manager.expire_due_blocks()
        assert report == {"expired": 1, "failed": 0}
        assert block2.status == BlockStatus.EXPIRED

    def test_approval_lifecycle_requires_admin(self, db_session, admin_id):
        manager = BlockManager(
            db_session, DryRunAdapter(WindowsFirewallAdapter()), actor_user_id=admin_id
        )
        pending = manager.block_ip(
            DUMMY_IP, reason="pending", requires_approval=True, manual=True
        )
        assert pending.status == BlockStatus.PENDING_APPROVAL

        approved = manager.approve_block(int(pending.id), actor_user_id=admin_id)
        assert approved.status == BlockStatus.ACTIVE
        assert approved.is_dry_run is True

        pending2 = manager.block_ip(
            "45.33.32.158", reason="pending2", requires_approval=True, manual=True
        )
        rejected = manager.reject_block(int(pending2.id), actor_user_id=admin_id)
        assert rejected.status == BlockStatus.RELEASED

    def test_reconcile_reports_drift_without_executing(self, db_session):
        class FakeAdapter(DryRunAdapter):
            def list_rules(self):
                return ["AI-IDS-unexpected0"]

        adapter = FakeAdapter(WindowsFirewallAdapter())
        manager = BlockManager(db_session, adapter)
        # Insert an active block directly; dry-run block creation needs an actor,
        # which is irrelevant to the reconciliation comparison itself.
        from core.models.prevention import BlockedIP

        db_session.add(
            BlockedIP(
                ip_address=DUMMY_IP,
                reason="seed",
                status=BlockStatus.ACTIVE,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                is_dry_run=True,
                firewall_rule_name=adapter.rule_name(DUMMY_IP),
            )
        )
        db_session.flush()
        drift = manager.reconcile()
        assert drift["mode"] == "dry-run"
        assert adapter.rule_name(DUMMY_IP) in drift["missing_rules"]
        assert "AI-IDS-unexpected0" in drift["unexpected_rules"]

    def test_failed_firewall_action_raises_and_records_failure(
        self, db_session, admin_id
    ):
        class FailingAdapter(DryRunAdapter):
            def block(self, ip, duration_minutes):
                return CommandResult(
                    success=False,
                    dry_run=False,
                    preview="[]",
                    stderr="permission denied",
                )

        manager = BlockManager(db_session, FailingAdapter(WindowsFirewallAdapter()))
        with pytest.raises(RuntimeError, match="permission denied"):
            manager.block_ip(
                DUMMY_IP, reason="failure", manual=True, actor_user_id=admin_id
            )
        action = (
            db_session.execute(
                select(PreventionAction).order_by(PreventionAction.id.desc())
            )
            .scalars()
            .first()
        )
        assert action.result == "FAILED"
        assert "permission denied" in action.error

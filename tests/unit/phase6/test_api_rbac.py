"""Executable RBAC matrix for every Phase 6 /api/v1 route."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from core.config import settings
from core.db import get_db_session
from core.events import utc_now
from core.models.alert import AlertStatus
from core.models.detection import Detection
from core.models.network import NetworkFlow
from core.models.prevention import BlockedIP, BlockStatus
from core.models.threat import IPProfile
from core.models.user import UserRole
from utils.alerts import create_alert_from_detection

_CSRF_META_RE = re.compile(r'<meta name="csrf-token" content="([^"]+)"')

PUBLIC_IP = "45.33.32.156"
ALL_ROLES = frozenset({UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER})
TRIAGE_ROLES = frozenset({UserRole.ADMIN, UserRole.ANALYST})
ADMIN_ONLY = frozenset({UserRole.ADMIN})


@dataclass(frozen=True)
class RouteCase:
    name: str
    method: str
    path: str
    allowed: frozenset[UserRole]
    success_status: int = 200
    payload: dict[str, Any] | None = None


def _csrf(client: Any, path: str = "/login") -> str:
    body = client.get(path).get_data(as_text=True)
    match = _CSRF_META_RE.search(body)
    assert match is not None, f"No CSRF token rendered on {path!r}"
    return match.group(1)


def _call(
    client: Any,
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    token: str | None,
):
    headers = {"X-CSRFToken": token} if token and method != "GET" else {}
    return client.open(path, method=method, json=payload, headers=headers)


@pytest.fixture
def api_resources(make_user):
    """Provision minimal persisted rows so route handlers reach their logic."""

    target_id = make_user("assign_target", role=UserRole.ANALYST)
    with get_db_session() as db_session:
        db_session.add(
            IPProfile(
                ip_address=PUBLIC_IP,
                detection_count=2,
                attack_types_json=json.dumps(["PortScan"]),
                max_severity="high",
            )
        )
        db_session.flush()

        def _block(ip: str, status: BlockStatus = BlockStatus.ACTIVE) -> int:
            row = BlockedIP(
                ip_address=ip,
                reason="rbac fixture",
                status=status,
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
                is_dry_run=True,
                firewall_rule_name="AI-IDS-rbac-fixture",
            )
            db_session.add(row)
            db_session.flush()
            return int(row.id)

        def _alert(ip: str, sequence: int) -> int:
            flow = NetworkFlow(
                flow_id=f"rbac-flow-{sequence}",
                timestamp=utc_now(),
                src_ip=ip,
                src_port=40000 + sequence,
                dst_ip="104.16.1.10",
                dst_port=443,
                protocol="TCP",
                features_json="{}",
            )
            db_session.add(flow)
            db_session.flush()
            detection = Detection(
                flow_id=int(flow.id),
                predicted_label="PortScan",
                is_malicious=True,
                confidence_score=0.96,
                is_anomaly=False,
                anomaly_score=0.1,
                model_version="cicids-80k-no-port",
            )
            db_session.add(detection)
            db_session.flush()
            return int(create_alert_from_detection(db_session, detection).id)

        resource_ids = {
            "extend_block": _block("45.33.32.160"),
            "unblock": _block("45.33.32.161"),
            "approve": _block("45.33.32.162", BlockStatus.PENDING_APPROVAL),
            "reject": _block("45.33.32.163", BlockStatus.PENDING_APPROVAL),
            "detail_alert": _alert("45.33.32.150", 1),
            "status_alert": _alert("45.33.32.151", 2),
            "assign_alert": _alert("45.33.32.152", 3),
            "comment_alert": _alert("45.33.32.153", 4),
            "feedback_alert": _alert("45.33.32.154", 5),
            "target_user": target_id,
        }
    return resource_ids


@pytest.fixture
def route_cases(api_resources) -> list[RouteCase]:
    r = api_resources
    return [
        RouteCase("blocks list", "GET", "/api/v1/prevention/blocked-ips", ALL_ROLES),
        RouteCase(
            "block create",
            "POST",
            "/api/v1/prevention/blocked-ips",
            ADMIN_ONLY,
            201,
            {"ip_address": "45.33.32.164", "reason": "rbac", "duration_minutes": 5},
        ),
        RouteCase(
            "block extend",
            "POST",
            f"/api/v1/prevention/blocked-ips/{r['extend_block']}/extend",
            ADMIN_ONLY,
            200,
            {"additional_minutes": 5},
        ),
        RouteCase(
            "block unblock",
            "POST",
            f"/api/v1/prevention/blocked-ips/{r['unblock']}/unblock",
            ADMIN_ONLY,
            200,
            {"reason": "rbac"},
        ),
        RouteCase("whitelist list", "GET", "/api/v1/prevention/whitelist", ALL_ROLES),
        RouteCase(
            "whitelist add",
            "POST",
            "/api/v1/prevention/whitelist",
            ADMIN_ONLY,
            201,
            {"cidr": "45.33.32.0/27", "description": "rbac fixture"},
        ),
        RouteCase("policy get", "GET", "/api/v1/prevention/policy", ALL_ROLES),
        RouteCase(
            "policy update",
            "PUT",
            "/api/v1/prevention/policy",
            ADMIN_ONLY,
            200,
            {"kill_switch": False},
        ),
        RouteCase("approvals list", "GET", "/api/v1/prevention/approvals", ADMIN_ONLY),
        RouteCase(
            "block approve",
            "POST",
            f"/api/v1/prevention/approvals/{r['approve']}/approve",
            ADMIN_ONLY,
        ),
        RouteCase(
            "block reject",
            "POST",
            f"/api/v1/prevention/approvals/{r['reject']}/reject",
            ADMIN_ONLY,
        ),
        RouteCase("alerts list", "GET", "/api/v1/alerts", ALL_ROLES),
        RouteCase(
            "alert detail", "GET", f"/api/v1/alerts/{r['detail_alert']}", ALL_ROLES
        ),
        RouteCase(
            "alert status",
            "POST",
            f"/api/v1/alerts/{r['status_alert']}/status",
            TRIAGE_ROLES,
            200,
            {"status": AlertStatus.ACKNOWLEDGED.value, "notes": "rbac"},
        ),
        RouteCase(
            "alert assign",
            "POST",
            f"/api/v1/alerts/{r['assign_alert']}/assign",
            TRIAGE_ROLES,
            200,
            {"user_id": r["target_user"]},
        ),
        RouteCase(
            "alert comment",
            "POST",
            f"/api/v1/alerts/{r['comment_alert']}/comments",
            TRIAGE_ROLES,
            201,
            {"comment": "rbac"},
        ),
        RouteCase(
            "alert feedback",
            "POST",
            f"/api/v1/alerts/{r['feedback_alert']}/feedback",
            TRIAGE_ROLES,
            201,
            {"is_false_positive": True, "verified_label": "Benign"},
        ),
        RouteCase(
            "ip profile", "GET", f"/api/v1/threat-intel/ips/{PUBLIC_IP}", ALL_ROLES
        ),
        RouteCase(
            "ip enrich",
            "POST",
            "/api/v1/threat-intel/enrich",
            ALL_ROLES,
            200,
            {"ip_address": PUBLIC_IP, "provider": "abuseipdb"},
        ),
        RouteCase(
            "blocklist import",
            "POST",
            "/api/v1/threat-intel/blocklist/import",
            ADMIN_ONLY,
            200,
            {"format": "csv", "payload": "45.33.32.170", "source": "rbac"},
        ),
        RouteCase(
            "blocklist export",
            "GET",
            "/api/v1/threat-intel/blocklist/export",
            ALL_ROLES,
        ),
        RouteCase(
            "key rotate",
            "POST",
            "/api/v1/keys/rotate",
            ADMIN_ONLY,
            200,
            {
                "key_id": "api-v3",
                "kek_env_var": "AI_IDS_RBAC_TEST_KEK",
                "activate": True,
            },
        ),
        RouteCase(
            "key rewrap",
            "POST",
            "/api/v1/keys/rewrap",
            ADMIN_ONLY,
            200,
            {"target_key_id": "api-v3", "batch_size": 10},
        ),
    ]


class TestPreventionApiRbac:
    def test_unauthenticated_requests_are_rejected(
        self, client, route_cases: list[RouteCase]
    ):
        for case in route_cases:
            token = _csrf(client, "/login") if case.method != "GET" else None
            response = _call(client, case.method, case.path, case.payload, token)
            assert response.status_code == 401, case.name

    @pytest.mark.parametrize(
        "role", [UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN]
    )
    def test_role_matrix(
        self,
        auth_client,
        route_cases: list[RouteCase],
        role: UserRole,
        monkeypatch,
    ):
        monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)
        monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", None)
        monkeypatch.setattr(settings, "APP_KEK_VERSION", "v1")
        monkeypatch.setattr(
            settings,
            "APP_KEK_REGISTRY",
            json.dumps({"v1": "ab" * 32, "v2": "ef" * 32}),
        )
        monkeypatch.setenv("AI_IDS_RBAC_TEST_KEK", "cd" * 32)

        client, _user_id = auth_client(f"matrix_{role.value}", role)
        token = _csrf(client, "/dashboard")

        for case in route_cases:
            response = _call(client, case.method, case.path, case.payload, token)
            if role in case.allowed:
                assert response.status_code == case.success_status, (
                    case.name,
                    response.status_code,
                    response.get_data(as_text=True)[:200],
                )
            else:
                assert response.status_code == 403, (
                    case.name,
                    response.status_code,
                    response.get_data(as_text=True)[:200],
                )

"""Threat-intelligence safety, caching, and import tests."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from core.config import settings
from core.models.threat import IPProfile, ThreatBlocklistEntry
from core.models.user import UserRole
from utils.threat_intel import (
    build_provider_url,
    cache_size,
    clear_cache,
    enrich_ip,
    export_blocklist,
    import_blocklist,
    ip_is_in_blocklist,
    is_public_ip,
    prune_expired_cache,
    update_profile,
)

PUBLIC_IP = "45.33.32.156"


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch):
    clear_cache()
    monkeypatch.setattr("prevention.policy._local_addresses", lambda: frozenset())
    yield
    clear_cache()


class FakeResponse:
    def __init__(self, status_code: int = 200, payload=None):
        self.status_code = status_code
        self._payload = payload or {"data": {"abuseConfidenceScore": 95}}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class TestSSRFProtection:
    @pytest.mark.parametrize(
        "ip", ["127.0.0.1", "10.0.0.5", "192.168.1.20", "169.254.169.254", "::1"]
    )
    def test_private_addresses_are_not_public(self, ip):
        assert is_public_ip(ip) is False

    def test_public_address_is_recognized(self):
        assert is_public_ip(PUBLIC_IP) is True

    def test_only_fixed_providers_and_public_ips_are_allowed(self):
        assert build_provider_url("abuseipdb", PUBLIC_IP) == (
            "https://api.abuseipdb.com/api/v2/check"
        )
        with pytest.raises(ValueError):
            build_provider_url("http://127.0.0.1:8000/collect", PUBLIC_IP)
        with pytest.raises(ValueError):
            build_provider_url("abuseipdb", "127.0.0.1")

    def test_private_ip_is_never_sent_externally(self, db_session, monkeypatch):
        calls = []
        monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "fake-key")

        class Client:
            def get(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakeResponse()

        result = enrich_ip(
            db_session, "127.0.0.1", request_client=Client(), api_key="fake-key"
        )
        assert result == {"status": "skipped", "reason": "private_or_reserved"}
        assert calls == []


class TestEnrichment:
    def test_disabled_without_key_and_cached_results(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)
        calls = []

        class Client:
            def get(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakeResponse()

        client = Client()
        first = enrich_ip(db_session, PUBLIC_IP, request_client=client)
        second = enrich_ip(db_session, PUBLIC_IP, request_client=client)
        assert first == {"status": "disabled", "provider": "abuseipdb"}
        assert first == second
        assert calls == []
        assert cache_size() >= 1

    def test_success_uses_fixed_host_and_caches(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "fake-key")
        calls = []

        class Client:
            def get(self, url, **kwargs):
                calls.append((url, kwargs))
                return FakeResponse()

        client = Client()
        result = enrich_ip(db_session, PUBLIC_IP, request_client=client)
        assert result["status"] == "ok"
        assert calls[0][0] == "https://api.abuseipdb.com/api/v2/check"
        assert calls[0][1]["headers"]["Key"] == "fake-key"
        assert "fake-key" not in json.dumps(result)

        enrich_ip(db_session, PUBLIC_IP, request_client=client)
        assert len(calls) == 1

    def test_failures_are_contained(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "fake-key")

        class RateLimited:
            def get(self, *args, **kwargs):
                return FakeResponse(status_code=429)

        assert (
            enrich_ip(db_session, PUBLIC_IP, request_client=RateLimited())["status"]
            == "rate_limited"
        )
        clear_cache()

        class Broken:
            def get(self, *args, **kwargs):
                raise ConnectionError("offline")

        assert (
            enrich_ip(db_session, PUBLIC_IP, request_client=Broken())["status"]
            == "unavailable"
        )

    def test_cache_pruning(self, monkeypatch):
        monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)
        monkeypatch.setattr(settings, "THREAT_INTEL_CACHE_TTL_SECONDS", -1)
        enrich_ip(None, PUBLIC_IP)  # type: ignore[arg-type]
        assert prune_expired_cache(now=0) == 0
        assert prune_expired_cache() == 1


class TestProfilesAndBlocklist:
    def test_profile_rolls_up_detections_and_severity(self, db_session, make_detection):
        _flow, detection = make_detection(label="PortScan")
        update_profile(
            db_session,
            PUBLIC_IP,
            severity="low",
            detection=detection,
            resolve_dns=False,
        )
        profile = (
            db_session.execute(
                select(IPProfile).where(IPProfile.ip_address == PUBLIC_IP)
            )
            .scalars()
            .one()
        )
        update_profile(
            db_session,
            PUBLIC_IP,
            severity="critical",
            detection=detection,
            resolve_dns=False,
        )
        assert profile.detection_count == 2
        assert profile.max_severity == "critical"
        assert "PortScan" in json.loads(profile.attack_types_json)

    def test_import_validates_protected_and_invalid_addresses(
        self, db_session, make_user
    ):
        admin_id = make_user("intel_admin", role=UserRole.ADMIN)
        result = import_blocklist(
            db_session,
            "45.33.32.156\n45.33.32.157\n# comment\n",
            format="csv",
            actor_user_id=admin_id,
        )
        assert result == {"received": 2, "imported": 2}
        assert ip_is_in_blocklist(db_session, PUBLIC_IP) is True
        assert (
            len(db_session.execute(select(ThreatBlocklistEntry)).scalars().all()) == 2
        )

        again = import_blocklist(db_session, "45.33.32.156", actor_user_id=admin_id)
        assert again["imported"] == 0

        with pytest.raises(ValueError):
            import_blocklist(db_session, "1.2.3.4; evil", actor_user_id=admin_id)
        with pytest.raises(ValueError):
            import_blocklist(db_session, "127.0.0.1", actor_user_id=admin_id)

    def test_import_requires_admin_and_enforces_size_limit(
        self, db_session, make_user, monkeypatch
    ):
        viewer_id = make_user("intel_viewer", role=UserRole.VIEWER)
        with pytest.raises(PermissionError):
            import_blocklist(db_session, PUBLIC_IP, actor_user_id=viewer_id)

        monkeypatch.setattr(settings, "THREAT_INTEL_MAX_IMPORT_BYTES", 4)
        with pytest.raises(ValueError, match="exceeds"):
            import_blocklist(db_session, PUBLIC_IP)

    def test_export_roundtrip(self, db_session, make_user):
        admin_id = make_user("intel_admin2", role=UserRole.ADMIN)
        import_blocklist(db_session, PUBLIC_IP, actor_user_id=admin_id)
        exported_json = export_blocklist(db_session, format="json")
        assert json.loads(exported_json)[0]["ip_address"] == PUBLIC_IP
        exported_csv = export_blocklist(db_session, format="csv")
        assert "ip_address,source,reason" in exported_csv
        assert PUBLIC_IP in exported_csv

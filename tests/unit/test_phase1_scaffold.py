"""Phase 1 Verification Tests.

Validates:
1. Pydantic settings parsing, KEK validation, and whitelist network expansion.
2. Structured JSON and CEF logging with sensitive data redaction.
3. SQLAlchemy 2.0 ORM model integrity and relationships on an in-memory SQLite engine.
4. Tamper-evident hash-chaining logic on audit ledger entries.
5. Critical deployment configuration files integrity.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.db import Base
from core.logging import (
    CEFFormatter,
    StructuredJsonFormatter,
    get_correlation_id,
    redact_sensitive_data,
    set_correlation_id,
)
from core.models import (
    GENESIS_HASH,
    Alert,
    AlertSeverity,
    AlertStatus,
    AuditLog,
    BlockedIP,
    BlockStatus,
    Detection,
    NetworkFlow,
    User,
    UserRole,
    Whitelist,
)


class TestConfiguration:
    """Verifies core/config.py settings and validation logic."""

    def test_default_settings(self):
        s = Settings()
        assert s.APP_NAME == "AI-IDS/IPS Enterprise Defensive Platform"
        assert s.PREVENTION_MODE in ["dry_run", "active"]
        assert len(s.APP_MASTER_KEK) == 64
        assert s.PREVENTION_CONFIDENCE_THRESHOLD >= 0.5

    def test_kek_validation(self):
        # Valid 32-byte (64 hex char) KEK
        valid_kek = "a" * 64
        s = Settings(APP_MASTER_KEK=valid_kek)
        assert s.APP_MASTER_KEK == valid_kek

        # Invalid length
        with pytest.raises(ValueError, match="must be exactly 64 hex characters"):
            Settings(APP_MASTER_KEK="short_kek")

        # Invalid non-hex characters
        with pytest.raises(ValueError, match="valid hexadecimal"):
            Settings(APP_MASTER_KEK="z" * 64)

    def test_whitelist_parsing(self):
        s = Settings(PREVENTION_WHITELIST="127.0.0.1/32, 10.0.0.0/8, 192.168.1.1/32, invalid_cidr")
        parsed = s.get_parsed_whitelist()
        assert len(parsed) == 3
        cidrs = [str(net) for net in parsed]
        assert "127.0.0.1/32" in cidrs
        assert "10.0.0.0/8" in cidrs
        assert "192.168.1.1/32" in cidrs


class TestStructuredLogging:
    """Verifies core/logging.py JSON formatting, CEF generation, and redaction."""

    def test_correlation_id_tracking(self):
        custom_cid = "test-corr-id-12345"
        set_correlation_id(custom_cid)
        assert get_correlation_id() == custom_cid

    def test_sensitive_field_redaction(self):
        raw_payload = {
            "username": "sec_analyst",
            "password": "SuperSecretPassword123!",
            "nested": {
                "api_key": "secret_key_abc",
                "normal_field": "visible_value",
            },
        }
        redacted = redact_sensitive_data(raw_payload)
        assert redacted["username"] == "sec_analyst"
        assert redacted["password"] == "[REDACTED]"
        assert redacted["nested"]["api_key"] == "[REDACTED]"
        assert redacted["nested"]["normal_field"] == "visible_value"

    def test_json_formatter(self):
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Flow analyzed",
            args=(),
            exc_info=None,
        )
        record.correlation_id = "cid-999"
        record.extra_data = {"flow_bytes": 1024, "token": "sensitive"}

        formatted = formatter.format(record)
        data = json.loads(formatted)
        assert data["level"] == "INFO"
        assert data["message"] == "Flow analyzed"
        assert data["correlation_id"] == "cid-999"
        assert data["data"]["flow_bytes"] == 1024
        assert data["data"]["token"] == "[REDACTED]"

    def test_cef_formatter(self):
        formatter = CEFFormatter()
        record = logging.LogRecord(
            name="security_logger",
            level=logging.WARNING,
            pathname=__file__,
            lineno=20,
            msg="Potential PortScan Detected",
            args=(),
            exc_info=None,
        )
        record.correlation_id = "cid-cef-1"
        record.event_type = "IDS_SCAN_ALERT"
        record.extra_data = {"src_ip": "10.0.0.5"}

        cef_str = formatter.format(record)
        assert cef_str.startswith("CEF:0|AI-IDS-IPS|EnterpriseDefense|1.0.0|IDS_SCAN_ALERT|Potential PortScan Detected|6|")
        assert "src_ip=10.0.0.5" in cef_str


class TestDatabaseModelsAndIntegrity:
    """Verifies all SQLAlchemy 2.0 ORM models and relationships on in-memory SQLite."""

    @pytest.fixture
    def db_session(self):
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        yield session
        session.close()

    def test_user_creation_and_defaults(self, db_session: Session):
        user = User(
            username="admin",
            email="admin@test.local",
            password_hash="argon2id_hash_placeholder",
            role=UserRole.ADMIN,
        )
        db_session.add(user)
        db_session.commit()

        queried = db_session.query(User).filter_by(username="admin").first()
        assert queried is not None
        assert queried.role == UserRole.ADMIN
        assert queried.is_active is True
        assert queried.must_change_password is True
        assert queried.failed_login_attempts == 0

    def test_flow_detection_alert_relationship(self, db_session: Session):
        # 1. Create NetworkFlow
        flow = NetworkFlow(
            flow_id="192.168.1.100:443-10.0.0.5:54321-TCP",
            src_ip="192.168.1.100",
            src_port=443,
            dst_ip="10.0.0.5",
            dst_port=54321,
            protocol="TCP",
            duration=1.25,
            total_fwd_packets=10,
            total_bwd_packets=8,
            total_fwd_bytes=1500,
            total_bwd_bytes=1200,
            flow_bytes_per_sec=2160.0,
            flow_packets_per_sec=14.4,
            features_json='{"flow_duration": 1.25, "total_fwd_packets": 10}',
        )
        db_session.add(flow)
        db_session.flush()

        # 2. Attach Detection
        detection = Detection(
            flow_id=flow.id,
            predicted_label="DoS Hulk",
            is_malicious=True,
            confidence_score=0.98,
            is_anomaly=False,
            model_version="1.0.0",
            top_features_json='["fwd_pkt_len_mean", "flow_iat_min"]',
        )
        db_session.add(detection)
        db_session.flush()

        # 3. Attach Alert
        alert = Alert(
            detection_id=detection.id,
            dedup_key="dedup-hulk-192.168.1.100",
            title="High-Confidence DoS Hulk Detected",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.NEW,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.5",
            dst_port=54321,
            attack_type="DoS Hulk",
        )
        db_session.add(alert)
        db_session.commit()

        # 4. Verify cross-model navigation
        queried_alert = db_session.query(Alert).first()
        assert queried_alert is not None
        assert queried_alert.detection.predicted_label == "DoS Hulk"
        assert queried_alert.detection.flow.src_ip == "192.168.1.100"

    def test_prevention_models(self, db_session: Session):
        now = datetime.now(UTC)
        block = BlockedIP(
            ip_address="198.51.100.5",
            reason="Repeated PortScan",
            status=BlockStatus.ACTIVE,
            blocked_at=now,
            expires_at=now,
            is_dry_run=True,
            firewall_rule_name="AI_BLOCK_198_51_100_5",
        )
        whitelist = Whitelist(
            cidr="127.0.0.1/32",
            description="Local Loopback",
            is_immutable=True,
        )
        db_session.add(block)
        db_session.add(whitelist)
        db_session.commit()

        assert db_session.query(BlockedIP).count() == 1
        assert db_session.query(Whitelist).count() == 1

    def test_tamper_evident_audit_hash_chain(self, db_session: Session):
        hmac_key = "test_hmac_secret_key"
        t1 = datetime.now(UTC).isoformat()

        # Genesis Entry
        hash_1 = AuditLog.compute_hash(
            hmac_key=hmac_key,
            prev_hash=GENESIS_HASH,
            timestamp=t1,
            user_id=1,
            action="USER_LOGIN",
            resource_type="USER",
            resource_id="1",
            status="SUCCESS",
            details_json='{"ip": "127.0.0.1"}',
        )
        entry_1 = AuditLog(
            username="admin",
            action="USER_LOGIN",
            resource_type="USER",
            resource_id="1",
            status="SUCCESS",
            details='{"ip": "127.0.0.1"}',
            previous_hash=GENESIS_HASH,
            entry_hash=hash_1,
        )
        db_session.add(entry_1)
        db_session.commit()

        # Second Entry chained to Genesis
        t2 = datetime.now(UTC).isoformat()
        hash_2 = AuditLog.compute_hash(
            hmac_key=hmac_key,
            prev_hash=entry_1.entry_hash,
            timestamp=t2,
            user_id=1,
            action="FIREWALL_POLICY_CHANGE",
            resource_type="POLICY",
            resource_id="global",
            status="SUCCESS",
            details_json='{"mode": "active"}',
        )
        entry_2 = AuditLog(
            username="admin",
            action="FIREWALL_POLICY_CHANGE",
            resource_type="POLICY",
            resource_id="global",
            status="SUCCESS",
            details='{"mode": "active"}',
            previous_hash=entry_1.entry_hash,
            entry_hash=hash_2,
        )
        db_session.add(entry_2)
        db_session.commit()

        # Verify chain integrity
        entries = db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
        assert len(entries) == 2
        assert entries[0].previous_hash == GENESIS_HASH
        assert entries[1].previous_hash == entries[0].entry_hash

        # Test tamper detection: simulate unauthorized DB modification
        tampered_hash = AuditLog.compute_hash(
            hmac_key=hmac_key,
            prev_hash=entries[0].entry_hash,
            timestamp=t2,
            user_id=1,
            action="FIREWALL_POLICY_CHANGE_TAMPERED",  # Tampered action
            resource_type="POLICY",
            resource_id="global",
            status="SUCCESS",
            details_json='{"mode": "active"}',
        )
        assert tampered_hash != entries[1].entry_hash


class TestProjectScaffoldAndDocker:
    """Verifies that all required files and directories from Phase 1 exist."""

    def test_critical_files_exist(self):
        base_dir = Path(__file__).resolve().parent.parent.parent
        expected_files = [
            base_dir / "requirements.txt",
            base_dir / "requirements-dev.txt",
            base_dir / ".env.example",
            base_dir / ".gitignore",
            base_dir / "Makefile",
            base_dir / "run.py",
            base_dir / "alembic.ini",
            base_dir / "migrations" / "env.py",
            base_dir / "migrations" / "versions" / "0001_initial_schema.py",
            base_dir / "docker" / "Dockerfile.api",
            base_dir / "docker" / "Dockerfile.engine",
            base_dir / "docker" / "Dockerfile.worker",
            base_dir / "docker" / "nginx.conf",
            base_dir / "docker" / "docker-compose.yml",
            base_dir / "docker" / "docker-compose.prod.yml",
            base_dir / ".github" / "workflows" / "ci.yml",
            base_dir / "docs" / "architecture.md",
            base_dir / "docs" / "threat_model.md",
        ]
        for f in expected_files:
            assert f.exists(), f"Missing critical file: {f}"
            assert f.stat().st_size > 0, f"File is empty: {f}"

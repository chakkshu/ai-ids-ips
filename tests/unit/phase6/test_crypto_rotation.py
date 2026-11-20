"""Envelope encryption, key rotation, and resumable rewrap tests."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from core.config import settings
from core.crypto import (
    CryptoError,
    available_key_ids,
    current_key_id,
    decrypt,
    encrypt,
    encrypt_with_key_id,
    rewrap_envelope,
)
from core.models.audit import AuditLog
from core.models.user import User
from utils.crypto import (
    TOTP_PURPOSE,
    rewrap_sensitive_fields,
    rotate_kek,
)

V2_HEX = "ef" * 32
SECRET = "totp-shared-secret-abc123"


class TestEnvelopePrimitives:
    def test_roundtrip_hides_plaintext_and_binds_purpose(self):
        token = encrypt(SECRET, purpose=TOTP_PURPOSE)
        assert SECRET not in token
        assert token.startswith("env:")
        assert len(token.split(":")) == 6
        assert decrypt(token, purpose=TOTP_PURPOSE) == SECRET
        with pytest.raises(CryptoError):
            decrypt(token, purpose="raw-payload")

    def test_tampering_is_detected(self):
        token = encrypt(SECRET, purpose=TOTP_PURPOSE)
        parts = token.split(":")
        parts[-1] = ("A" if parts[-1][0] != "A" else "B") + parts[-1][1:]
        with pytest.raises(CryptoError):
            decrypt(":".join(parts), purpose=TOTP_PURPOSE)

    def test_invalid_kek_material_is_rejected_without_echo(self):
        with pytest.raises(CryptoError) as exc:
            rotate_kek(key_id="v2", kek_hex="not-a-secret")
        assert "not-a-secret" not in str(exc.value)


class TestKeyRotation:
    def test_old_ciphertext_stays_readable_after_rotation(self, monkeypatch):
        monkeypatch.setattr(settings, "APP_KEK_REGISTRY", "{}")
        monkeypatch.setattr(settings, "APP_KEK_VERSION", "v1")

        old_token = encrypt(SECRET, purpose=TOTP_PURPOSE)
        assert current_key_id() == "v1"

        result = rotate_kek(key_id="v2", kek_hex=V2_HEX)
        assert result["active_key_id"] == "v2"
        assert result["previous_key_id"] == "v1"
        assert sorted(result["available_key_ids"]) == ["v1", "v2"]
        assert V2_HEX not in json.dumps(result)

        new_token = encrypt(SECRET, purpose=TOTP_PURPOSE)
        assert new_token.split(":")[1] == "v2"
        assert old_token.split(":")[1] == "v1"
        assert decrypt(old_token, purpose=TOTP_PURPOSE) == SECRET
        assert decrypt(new_token, purpose=TOTP_PURPOSE) == SECRET

        rewrapped = rewrap_envelope(old_token, purpose=TOTP_PURPOSE, target_key_id="v2")
        assert rewrapped.split(":")[1] == "v2"
        assert decrypt(rewrapped, purpose=TOTP_PURPOSE) == SECRET

    def test_encrypt_with_unregistered_key_is_refused(self, monkeypatch):
        monkeypatch.setattr(settings, "APP_KEK_REGISTRY", "{}")
        monkeypatch.setattr(settings, "APP_KEK_VERSION", "v1")
        with pytest.raises(CryptoError):
            encrypt_with_key_id(SECRET, TOTP_PURPOSE, "v9")


class TestRewrapService:
    def test_rewrap_is_audited_resumable_and_secret_free(
        self, db_session, make_user, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(settings, "APP_KEK_REGISTRY", "{}")
        monkeypatch.setattr(settings, "APP_KEK_VERSION", "v1")
        original = encrypt(SECRET, purpose=TOTP_PURPOSE)
        user_id = make_user("rewrapuser", totp_secret=original)
        rotate_kek(key_id="v2", kek_hex=V2_HEX)

        checkpoint = tmp_path / "rewrap.json"
        summary = rewrap_sensitive_fields(
            db_session, target_key_id="v2", checkpoint_path=checkpoint
        )
        assert summary["rewrapped"] == 1
        assert summary["tables"]["users"] == 1

        stored = db_session.get(User, user_id).totp_secret
        assert stored.startswith("env:v2:")
        assert decrypt(stored, purpose=TOTP_PURPOSE) == SECRET
        assert SECRET not in checkpoint.read_text(encoding="utf-8")
        assert V2_HEX not in checkpoint.read_text(encoding="utf-8")
        assert json.loads(checkpoint.read_text(encoding="utf-8"))["complete"] is True

        actions = {
            row.action for row in db_session.execute(select(AuditLog)).scalars().all()
        }
        assert "KEY_REWRAP_STARTED" in actions
        assert "KEY_REWRAP_COMPLETED" in actions

        # A second pass is idempotent: no envelope needs rewrapping.
        repeated = rewrap_sensitive_fields(
            db_session, target_key_id="v2", checkpoint_path=checkpoint
        )
        assert repeated["rewrapped"] == 0

    def test_rewrap_rejects_unregistered_target(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "APP_KEK_REGISTRY", "{}")
        monkeypatch.setattr(settings, "APP_KEK_VERSION", "v1")
        with pytest.raises(CryptoError):
            rewrap_sensitive_fields(db_session, target_key_id="unknown")

    def test_registered_key_ids_never_include_material(self, monkeypatch):
        monkeypatch.setattr(settings, "APP_KEK_REGISTRY", json.dumps({"v2": V2_HEX}))
        monkeypatch.setattr(settings, "APP_KEK_VERSION", "v1")
        assert set(available_key_ids()) == {"v1", "v2"}
        assert V2_HEX not in json.dumps(available_key_ids())

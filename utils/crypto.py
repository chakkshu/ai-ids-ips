"""High-level envelope-encryption services, rotation, and resumable rewrap.

This module is the service-layer entry point for encrypting/decrypting modeled
sensitive fields. Low-level AES-256-GCM primitives live in :mod:`core.crypto`.
No plaintext, key material, or API secret is ever logged or written to a
checkpoint file.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from core.crypto import (
    CryptoError,
    activate_kek_version,
    available_key_ids,
    current_key_id,
    decrypt,
    encrypt,
    is_envelope,
    rewrap_envelope,
    validate_kek_material,
)
from core.db import get_db_session
from core.logging import get_logger
from core.models.network import NetworkFlow
from core.models.user import User
from core.security import audit_details, log_security_event

logger = get_logger(__name__)

TOTP_PURPOSE = "totp-secret"
RAW_PAYLOAD_PURPOSE = "raw-payload"


@dataclass(frozen=True)
class SensitiveField:
    """Declarative description of one encrypted ORM column."""

    table: str
    model: Any
    column: str
    purpose: str


SENSITIVE_FIELDS: tuple[SensitiveField, ...] = (
    SensitiveField("users", User, "totp_secret", TOTP_PURPOSE),
    SensitiveField(
        "network_flows", NetworkFlow, "encrypted_payload", RAW_PAYLOAD_PURPOSE
    ),
)


def encrypt_sensitive(value: str, purpose: str) -> str:
    """Encrypt a sensitive value with the active KEK."""

    return encrypt(value, purpose=purpose)


def decrypt_sensitive(token: str, purpose: str) -> str:
    """Decrypt a sensitive value for an authorized service-layer caller."""

    return decrypt(token, purpose=purpose)


def rotate_kek(*, key_id: str, kek_hex: str, activate: bool = True) -> dict[str, Any]:
    """Register a new KEK and optionally make it the active write key.

    ``kek_hex`` must be supplied from a secret store or environment variable by
    the caller; it is never logged or included in the returned payload.
    """

    validate_kek_material(kek_hex)
    key_id = key_id.strip()
    if not key_id:
        raise CryptoError("key ID must not be empty")

    registry: dict[str, str] = {}
    try:
        parsed = json.loads(settings.APP_KEK_REGISTRY or "{}")
        if isinstance(parsed, dict):
            registry = {
                str(name): str(material)
                for name, material in parsed.items()
                if isinstance(name, str) and isinstance(material, str)
            }
    except json.JSONDecodeError as exc:
        raise CryptoError("KEK registry is not valid JSON") from exc

    previous_id = current_key_id()
    if key_id == previous_id:
        raise CryptoError("new KEK ID must differ from the active key ID")

    # Preserve the current key material even when it is configured only through
    # APP_MASTER_KEK. Without this, rotation would make existing envelopes
    # undecryptable as soon as the active write key changes.
    registry.setdefault(previous_id, validate_kek_material(settings.APP_MASTER_KEK))
    registry[key_id] = kek_hex.strip()
    object.__setattr__(
        settings, "APP_KEK_REGISTRY", json.dumps(registry, sort_keys=True)
    )
    if activate:
        activate_kek_version(key_id)

    return {
        "previous_key_id": previous_id,
        "active_key_id": current_key_id(),
        "available_key_ids": list(available_key_ids()),
        "activated": activate,
    }


def _read_checkpoint(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CryptoError("rewrap checkpoint is unreadable") from exc
    return payload if isinstance(payload, dict) else {}


def _write_checkpoint(path: Path | None, state: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)


def _audit_rewrap(
    action: str,
    status: str,
    details: dict[str, Any],
    actor_user_id: int | None,
    db_session: Session,
) -> None:
    """Record a rewrap lifecycle event without including plaintext."""

    log_security_event(
        action=action,
        resource_type="ENCRYPTION_KEY",
        resource_id=str(details.get("target_key_id") or "unknown"),
        user_id=actor_user_id,
        username="system" if actor_user_id is None else "operator",
        status=status,
        details=audit_details(**details),
        db_session=db_session,
    )


def rewrap_sensitive_fields(
    db_session: Session,
    *,
    target_key_id: str,
    actor_user_id: int | None = None,
    batch_size: int = 100,
    checkpoint_path: str | Path | None = None,
) -> dict[str, Any]:
    """Rewrap all modeled sensitive fields; safe to resume after interruption."""

    if batch_size <= 0:
        raise CryptoError("batch_size must be positive")
    if target_key_id not in available_key_ids():
        raise CryptoError("target key ID is not registered")

    checkpoint = Path(checkpoint_path) if checkpoint_path else None
    state = _read_checkpoint(checkpoint)
    summary: dict[str, Any] = {
        "target_key_id": target_key_id,
        "rewrapped": 0,
        "scanned": 0,
        "tables": {},
    }
    _audit_rewrap(
        "KEY_REWRAP_STARTED",
        "SUCCESS",
        {**summary, "resumed": bool(state)},
        actor_user_id,
        db_session,
    )

    try:
        for field in SENSITIVE_FIELDS:
            state_key = f"{field.table}:{field.column}"
            last_id = int(state.get(state_key, 0) or 0)
            column = getattr(field.model, field.column)
            rows = (
                db_session.execute(
                    select(field.model)
                    .where(column.is_not(None))
                    .where(column > "")
                    .where(field.model.id > last_id)
                    .order_by(field.model.id)
                    .limit(batch_size)
                )
                .scalars()
                .all()
            )
            table_count = 0
            for row in rows:
                token = getattr(row, field.column)
                if not is_envelope(token):
                    raise CryptoError("sensitive field contains a non-envelope value")
                setattr(
                    row,
                    field.column,
                    rewrap_envelope(token, field.purpose, target_key_id=target_key_id),
                )
                last_id = int(row.id)
                summary["scanned"] += 1
                if token.split(":")[1] != target_key_id:
                    table_count += 1
            if rows:
                state[state_key] = last_id
                db_session.flush()
                _write_checkpoint(checkpoint, {**state, "target_key_id": target_key_id})
            summary["tables"][field.table] = table_count
            summary["rewrapped"] += table_count

        state["complete"] = True
        state["target_key_id"] = target_key_id
        _write_checkpoint(checkpoint, state)
        _audit_rewrap(
            "KEY_REWRAP_COMPLETED",
            "SUCCESS",
            summary,
            actor_user_id,
            db_session,
        )
        return summary
    except Exception as exc:
        _audit_rewrap(
            "KEY_REWRAP_FAILED",
            "FAILED",
            {"target_key_id": target_key_id, "error_type": type(exc).__name__},
            actor_user_id,
            db_session,
        )
        raise


def _cmd_rotate(args: argparse.Namespace) -> int:
    material = os.environ.get(args.kek_env_var)
    if not material:
        logger.error("KEK environment variable is not set")
        return 2
    try:
        result = rotate_kek(
            key_id=args.key_id,
            kek_hex=material,
            activate=not args.register_only,
        )
    except CryptoError as exc:
        logger.error("KEK rotation failed: %s", exc)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def _cmd_rewrap(args: argparse.Namespace) -> int:
    with get_db_session() as db_session:
        result = rewrap_sensitive_fields(
            db_session,
            target_key_id=args.target_key_id,
            batch_size=args.batch_size,
            checkpoint_path=args.checkpoint,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for key rotation and resumable re-encryption."""

    parser = argparse.ArgumentParser(description="AES envelope key management")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rotate = subparsers.add_parser("rotate", help="register/activate a new KEK")
    rotate.add_argument("--key-id", required=True)
    rotate.add_argument(
        "--kek-env-var",
        default="AI_IDS_NEW_KEK",
        help="environment variable containing the 64-character hex KEK",
    )
    rotate.add_argument(
        "--register-only",
        action="store_true",
        help="register the key without changing the active write key",
    )
    rotate.set_defaults(handler=_cmd_rotate)

    rewrap = subparsers.add_parser("rewrap", help="re-encrypt sensitive fields")
    rewrap.add_argument("--target-key-id", required=True)
    rewrap.add_argument("--batch-size", type=int, default=100)
    rewrap.add_argument("--checkpoint", default=None)
    rewrap.set_defaults(handler=_cmd_rewrap)

    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":  # pragma: no cover - exercised by CLI smoke checks
    raise SystemExit(main())

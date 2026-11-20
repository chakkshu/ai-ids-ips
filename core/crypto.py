"""AES-256-GCM envelope encryption primitives.

Sensitive values are encrypted with a fresh data-encryption key (DEK). The DEK
is itself wrapped by a versioned key-encryption key (KEK) loaded from
environment configuration. Retired KEKs remain in the registry so old rows stay
readable after rotation.

Envelope format::

    env:<key_id>:<b64 wrap nonce>:<b64 wrapped DEK>:<b64 nonce>:<b64 ciphertext>

The purpose and key ID are bound as authenticated additional data (AAD), so a
ciphertext cannot be replayed for a different purpose or key version. Secrets,
keys, and plaintext values are never logged by this module.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import settings

ENVELOPE_PREFIX = "env"
_NONCE_BYTES = 12
_KEY_BYTES = 32
_HEX_KEY_LENGTH = _KEY_BYTES * 2


class CryptoError(ValueError):
    """Raised when an envelope is malformed, tampered with, or undecryptable."""


@dataclass(frozen=True)
class _KeyRegistry:
    """Snapshot of decryption-capable KEKs and the active write key ID."""

    current_id: str
    keys: dict[str, bytes]

    def current_key(self) -> bytes:
        return self.keys[self.current_id]

    def key_for(self, key_id: str) -> bytes:
        try:
            return self.keys[key_id]
        except KeyError as exc:
            raise CryptoError("unknown envelope key ID") from exc


def _as_bytes(value: str) -> bytes:
    """Decode a hexadecimal KEK into raw bytes expected by AESGCM."""

    return bytes.fromhex(value)


def validate_kek_material(value: str) -> str:
    """Validate a hex KEK without echoing the secret in any error message."""

    if not isinstance(value, str) or len(value.strip()) != _HEX_KEY_LENGTH:
        raise CryptoError("KEK must be exactly 64 hexadecimal characters")
    try:
        bytes.fromhex(value.strip())
    except ValueError as exc:
        raise CryptoError("KEK must be valid hexadecimal") from exc
    return value.strip()


def _key_registry() -> _KeyRegistry:
    """Build a key registry from the current settings snapshot."""

    current_id = settings.APP_KEK_VERSION.strip()
    if not current_id:
        raise CryptoError("active KEK version is not configured")

    keys: dict[str, bytes] = {
        current_id: _as_bytes(validate_kek_material(settings.APP_MASTER_KEK))
    }
    raw_registry = settings.APP_KEK_REGISTRY.strip() or "{}"
    try:
        parsed = json.loads(raw_registry)
    except json.JSONDecodeError as exc:
        raise CryptoError("KEK registry is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise CryptoError("KEK registry must be a JSON object")

    for key_id, material in parsed.items():
        if not isinstance(key_id, str) or not key_id.strip():
            raise CryptoError("KEK registry contains an invalid key ID")
        if not isinstance(material, str):
            raise CryptoError("KEK registry contains invalid key material")
        keys[key_id.strip()] = _as_bytes(validate_kek_material(material))
    return _KeyRegistry(current_id=current_id, keys=keys)


def current_key_id() -> str:
    """Return the key ID used for new encryptions."""

    return _key_registry().current_id


def available_key_ids() -> tuple[str, ...]:
    """Return registered key IDs (never the key material)."""

    return tuple(sorted(_key_registry().keys))


def activate_kek_version(key_id: str) -> str:
    """Set the active write key after verifying it exists in the registry."""

    registry = _key_registry()
    if key_id not in registry.keys:
        raise CryptoError("cannot activate an unregistered KEK version")
    object.__setattr__(settings, "APP_KEK_VERSION", key_id)
    return current_key_id()


def _aad(purpose: str, version: str) -> bytes:
    """Bind envelope purpose and key ID into authenticated data."""

    return f"ai-ids-ips|{purpose}|{version}".encode()


def _b64_encode(value: bytes) -> str:
    """URL-safe base64 without padding (safe for compact database columns)."""

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    """Decode URL-safe base64, restoring omitted padding."""

    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def encrypt_with_key_id(plaintext: str, purpose: str, key_id: str) -> str:
    """Encrypt with an explicitly selected registered KEK."""

    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")

    registry = _key_registry()
    if key_id not in registry.keys:
        raise CryptoError("cannot encrypt with an unregistered KEK version")

    aad = _aad(purpose, key_id)
    dek = AESGCM.generate_key(bit_length=_KEY_BYTES * 8)
    data_nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext.encode("utf-8"), aad)

    wrap_nonce = os.urandom(_NONCE_BYTES)
    wrapped_dek = AESGCM(registry.key_for(key_id)).encrypt(wrap_nonce, dek, aad)

    return ":".join(
        [
            ENVELOPE_PREFIX,
            key_id,
            _b64_encode(wrap_nonce),
            _b64_encode(wrapped_dek),
            _b64_encode(data_nonce),
            _b64_encode(ciphertext),
        ]
    )


def encrypt(plaintext: str, purpose: str = "generic") -> str:
    """Encrypt plaintext using a fresh DEK wrapped by the active KEK."""

    return encrypt_with_key_id(plaintext, purpose, _key_registry().current_id)


def decrypt(token: str, purpose: str = "generic") -> str:
    """Decrypt a versioned AES-256-GCM envelope and verify its purpose binding."""

    if not isinstance(token, str) or not token.startswith(f"{ENVELOPE_PREFIX}:"):
        raise CryptoError("unsupported or missing ciphertext envelope")

    parts = token.split(":")
    if len(parts) != 6:
        raise CryptoError("malformed ciphertext envelope")

    _, version, wrap_nonce_b64, wrapped_dek_b64, nonce_b64, ciphertext_b64 = parts
    if not version:
        raise CryptoError("malformed envelope key ID")

    registry = _key_registry()
    kek = registry.key_for(version)
    aad = _aad(purpose, version)
    try:
        wrapped_dek = _b64_decode(wrapped_dek_b64)
        dek = AESGCM(kek).decrypt(_b64_decode(wrap_nonce_b64), wrapped_dek, aad)
        if len(dek) != _KEY_BYTES:
            raise CryptoError("ciphertext authentication failed")
        plaintext = AESGCM(dek).decrypt(
            _b64_decode(nonce_b64), _b64_decode(ciphertext_b64), aad
        )
    except (InvalidTag, ValueError, TypeError) as exc:
        raise CryptoError("ciphertext authentication failed") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError("decrypted payload is not valid UTF-8") from exc


def rewrap_envelope(
    token: str,
    purpose: str = "generic",
    *,
    target_key_id: str | None = None,
) -> str:
    """Re-encrypt one envelope under a newer KEK without logging plaintext."""

    registry = _key_registry()
    target = target_key_id or registry.current_id
    if target not in registry.keys:
        raise CryptoError("cannot rewrap to an unregistered KEK version")
    plaintext = decrypt(token, purpose=purpose)
    original_key_id = token.split(":")[1]
    if target == original_key_id:
        return token
    del registry
    return encrypt_with_key_id(plaintext, purpose, target)


def is_envelope(value: str | None) -> bool:
    """Return True when the value looks like a versioned envelope."""

    return bool(value and value.startswith(f"{ENVELOPE_PREFIX}:"))


def encrypt_secret(secret: str) -> str:
    """Encrypt a TOTP shared secret with purpose binding."""

    return encrypt(secret, purpose="totp-secret")


def decrypt_secret(token: str) -> str:
    """Decrypt a TOTP shared secret with purpose binding."""

    return decrypt(token, purpose="totp-secret")

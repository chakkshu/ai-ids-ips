"""AES-256-GCM envelope encryption primitives.

Sensitive values (currently TOTP shared secrets) are encrypted with a fresh
data-encryption key (DEK). The DEK is itself wrapped by the configured master
key-encryption key (KEK). The serialized envelope contains the key version so
future KEK rotation can be performed without storing plaintext.

Envelope format::

    env:<version>:<b64 wrap nonce>:<b64 wrapped DEK>:<b64 nonce>:<b64 ciphertext>

The purpose string is bound as authenticated additional data (AAD) so a
ciphertext encrypted for one purpose cannot be replayed for another.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import settings

ENVELOPE_PREFIX = "env"
_NONCE_BYTES = 12
_DEK_BYTES = 32


class CryptoError(ValueError):
    """Raised when an envelope is malformed, tampered with, or undecryptable."""


def _as_bytes(value: str) -> bytes:
    """Decode a hexadecimal KEK into raw bytes expected by AESGCM."""
    return bytes.fromhex(value)


def _kek() -> bytes:
    """Return the configured 256-bit key-encryption key."""
    return _as_bytes(settings.APP_MASTER_KEK)


def _aad(purpose: str, version: str) -> bytes:
    """Bind envelope purpose and key version into authenticated data."""
    return f"ai-ids-ips|{purpose}|{version}".encode()


def _b64_encode(value: bytes) -> str:
    """URL-safe base64 without padding (safe for compact database columns)."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    """Decode URL-safe base64, restoring omitted padding."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def encrypt(plaintext: str, purpose: str = "generic") -> str:
    """Encrypt plaintext using a fresh DEK wrapped by the master KEK."""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")

    version = settings.APP_KEK_VERSION
    aad = _aad(purpose, version)

    dek = AESGCM.generate_key(bit_length=_DEK_BYTES * 8)
    data_nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext.encode("utf-8"), aad)

    wrap_nonce = os.urandom(_NONCE_BYTES)
    wrapped_dek = AESGCM(_kek()).encrypt(wrap_nonce, dek, aad)

    return ":".join(
        [
            ENVELOPE_PREFIX,
            version,
            _b64_encode(wrap_nonce),
            _b64_encode(wrapped_dek),
            _b64_encode(data_nonce),
            _b64_encode(ciphertext),
        ]
    )


def decrypt(token: str, purpose: str = "generic") -> str:
    """Decrypt a versioned AES-256-GCM envelope and verify its purpose binding."""
    if not isinstance(token, str) or not token.startswith(f"{ENVELOPE_PREFIX}:"):
        raise CryptoError("unsupported or missing ciphertext envelope")

    parts = token.split(":")
    if len(parts) != 6:
        raise CryptoError("malformed ciphertext envelope")

    _, version, wrap_nonce_b64, wrapped_dek_b64, nonce_b64, ciphertext_b64 = parts
    if version != settings.APP_KEK_VERSION:
        raise CryptoError(f"unsupported envelope key version: {version}")

    aad = _aad(purpose, version)
    try:
        wrapped_dek = _b64_decode(wrapped_dek_b64)
        dek = AESGCM(_kek()).decrypt(_b64_decode(wrap_nonce_b64), wrapped_dek, aad)
        plaintext = AESGCM(dek).decrypt(
            _b64_decode(nonce_b64), _b64_decode(ciphertext_b64), aad
        )
    except (InvalidTag, ValueError, TypeError) as exc:
        raise CryptoError("ciphertext authentication failed") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError("decrypted payload is not valid UTF-8") from exc


def is_envelope(value: str | None) -> bool:
    """Return True when the value looks like a versioned envelope."""
    return bool(value and value.startswith(f"{ENVELOPE_PREFIX}:"))


def encrypt_secret(secret: str) -> str:
    """Encrypt a TOTP shared secret with purpose binding."""
    return encrypt(secret, purpose="totp-secret")


def decrypt_secret(token: str) -> str:
    """Decrypt a TOTP shared secret with purpose binding."""
    return decrypt(token, purpose="totp-secret")

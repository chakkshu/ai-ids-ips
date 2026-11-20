"""Threat-intelligence profiles, optional enrichment, and blocklist handling.

External providers are disabled unless an API key is configured. Only fixed
provider hostnames are ever contacted; user-supplied URLs are rejected. Private
and reserved addresses are never sent to an external service.
"""

from __future__ import annotations

import csv
import io
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from core.logging import get_logger
from core.models.alert import AlertSeverity
from core.models.detection import Detection
from core.models.threat import IPProfile, ThreatBlocklistEntry
from core.models.user import User, UserRole
from prevention.policy import (
    build_context,
    is_protected_ip,
    is_whitelisted_ip,
    parse_ip,
)

logger = get_logger(__name__)

ALLOWED_PROVIDERS: dict[str, tuple[str, str]] = {
    "abuseipdb": ("api.abuseipdb.com", "/api/v2/check"),
    "virustotal": ("www.virustotal.com", "/api/v3/ip_addresses/{ip}"),
}


@dataclass(frozen=True)
class _CacheEntry:
    value: dict[str, Any]
    expires_at: float


_cache_lock = threading.Lock()
_enrichment_cache: dict[tuple[str, str], _CacheEntry] = {}


def clear_cache() -> None:
    """Clear the in-process TTL cache (primarily for tests)."""

    with _cache_lock:
        _enrichment_cache.clear()


def is_public_ip(ip: str) -> bool:
    """Return True only for globally routable addresses safe for enrichment."""

    try:
        address = parse_ip(ip)
    except ValueError:
        return False
    return address.is_global and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def build_provider_url(provider: str, ip: str) -> str:
    """Build a fixed-host provider URL; never accept caller-supplied URLs."""

    normalized = provider.strip().lower()
    if normalized not in ALLOWED_PROVIDERS:
        raise ValueError("unsupported threat-intelligence provider")
    if not is_public_ip(ip):
        raise ValueError("private or reserved IPs are never sent externally")
    host, path_template = ALLOWED_PROVIDERS[normalized]
    path = path_template.format(ip=str(parse_ip(ip)))
    return f"https://{host}{path}"


def _provider_key(provider: str) -> str | None:
    if provider == "abuseipdb":
        return settings.ABUSEIPDB_API_KEY
    if provider == "virustotal":
        return settings.VIRUSTOTAL_API_KEY
    return None


def _cache_get(key: tuple[str, str]) -> dict[str, Any] | None:
    with _cache_lock:
        entry = _enrichment_cache.get(key)
        if entry is None:
            return None
        if entry.expires_at <= time.time():
            _enrichment_cache.pop(key, None)
            return None
        return entry.value


def _cache_set(key: tuple[str, str], value: dict[str, Any]) -> None:
    expires = time.time() + settings.THREAT_INTEL_CACHE_TTL_SECONDS
    with _cache_lock:
        _enrichment_cache[key] = _CacheEntry(value=value, expires_at=expires)


def _severity_rank(value: str) -> int:
    try:
        return {
            AlertSeverity.LOW: 0,
            AlertSeverity.MEDIUM: 1,
            AlertSeverity.HIGH: 2,
            AlertSeverity.CRITICAL: 3,
        }[AlertSeverity(value.lower())]
    except ValueError:
        return 0


def _reverse_dns(ip: str) -> str | None:
    """Best-effort reverse DNS with a hard timeout."""

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(socket.gethostbyaddr, str(parse_ip(ip)))
            return str(future.result(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS)[0])
    except (FutureTimeout, OSError, ValueError, IndexError):
        return None


def update_profile(
    db_session: Session,
    ip: str,
    *,
    attack_type: str | None = None,
    severity: str = "low",
    detection: Detection | None = None,
    resolve_dns: bool = True,
) -> IPProfile:
    """Create or update the rolling profile for one observed source IP."""

    address = str(parse_ip(ip))
    now = datetime.now(UTC)
    profile = (
        db_session.execute(select(IPProfile).where(IPProfile.ip_address == address))
        .scalars()
        .first()
    )
    if profile is None:
        profile = IPProfile(
            ip_address=address,
            first_seen=now,
            last_seen=now,
            detection_count=0,
            attack_types_json="[]",
            max_severity="low",
        )
        db_session.add(profile)

    label = attack_type or (detection.predicted_label if detection else "unknown")
    attack_types = set(json.loads(profile.attack_types_json or "[]"))
    attack_types.add(label)
    profile.attack_types_json = json.dumps(sorted(attack_types), sort_keys=True)
    profile.detection_count = int(profile.detection_count) + 1
    profile.last_seen = now
    if _severity_rank(severity) > _severity_rank(profile.max_severity):
        profile.max_severity = severity.lower()
    if resolve_dns and not profile.reverse_dns and is_public_ip(address):
        profile.reverse_dns = _reverse_dns(address)
    db_session.flush()
    return profile


def enrich_ip(
    db_session: Session,
    ip: str,
    *,
    provider: str = "abuseipdb",
    api_key: str | None = None,
    request_client: Any = None,
) -> dict[str, Any]:
    """Enrich a public IP using a fixed provider, with TTL caching."""

    if provider not in ALLOWED_PROVIDERS:
        raise ValueError("unsupported threat-intelligence provider")
    address = str(parse_ip(ip))
    if not is_public_ip(address):
        return {"status": "skipped", "reason": "private_or_reserved"}

    key = (provider, address)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    secret = api_key or _provider_key(provider)
    if not secret:
        result = {"status": "disabled", "provider": provider}
        _cache_set(key, result)
        return result

    url = build_provider_url(provider, address)
    client = request_client or requests
    headers = (
        {"Key": secret, "Accept": "application/json"}
        if provider == "abuseipdb"
        else {"x-apikey": secret, "Accept": "application/json"}
    )
    params = (
        {"ipAddress": address, "maxAgeInDays": 90} if provider == "abuseipdb" else None
    )
    try:
        response = client.get(
            url,
            headers=headers,
            params=params,
            timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS,
        )
        if getattr(response, "status_code", 500) == 429:
            result = {"status": "rate_limited", "provider": provider}
        else:
            response.raise_for_status()
            payload = response.json()
            result = {"status": "ok", "provider": provider, "data": payload}
    except Exception as exc:  # noqa: BLE001 - external integration boundary
        logger.warning(
            "Threat enrichment failed for provider %s: %s", provider, type(exc).__name__
        )
        result = {"status": "unavailable", "provider": provider}

    _cache_set(key, result)
    profile = (
        db_session.execute(select(IPProfile).where(IPProfile.ip_address == address))
        .scalars()
        .first()
    )
    if profile is not None:
        profile.enrichment_json = json.dumps(result, sort_keys=True, default=str)
        profile.last_enriched_at = datetime.now(UTC)
        db_session.flush()
    return result


def _validate_import_entries(
    db_session: Session, entries: list[dict[str, Any]]
) -> list[str]:
    """Validate size, syntax, and protected-address policy for an import."""

    context = build_context(db_session)
    normalized: list[str] = []
    for entry in entries:
        raw = str(entry.get("ip_address") or entry.get("ip") or "").strip()
        try:
            address = str(parse_ip(raw))
        except ValueError as exc:
            raise ValueError("blocklist contains an invalid IP address") from exc
        if is_protected_ip(address, context) or is_whitelisted_ip(address, context):
            raise ValueError("blocklist contains a protected address")
        normalized.append(address)
    return normalized


def _parse_import(payload: str, format: Literal["csv", "json"]) -> list[dict[str, Any]]:
    if format == "json":
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON blocklist") from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("indicators", [])
        if not isinstance(parsed, list) or len(parsed) > 10_000:
            raise ValueError("JSON blocklist must be a bounded list")
        entries = []
        for item in parsed:
            if isinstance(item, str):
                entries.append({"ip_address": item})
            elif isinstance(item, dict):
                entries.append(item)
            else:
                raise ValueError("invalid JSON blocklist entry")  # noqa: TRY004
        return entries

    reader = csv.DictReader(io.StringIO(payload))
    if reader.fieldnames and any("ip" in name.lower() for name in reader.fieldnames):
        return [dict(row) for row in reader]
    return [
        {"ip_address": line.strip()}
        for line in payload.splitlines()
        if line.strip() and not line.startswith("#")
    ]


def import_blocklist(
    db_session: Session,
    payload: str,
    *,
    format: Literal["csv", "json"] = "csv",
    source: str = "operator-import",
    actor_user_id: int | None = None,
) -> dict[str, int]:
    """Import a strictly validated local blocklist."""

    if len(payload.encode("utf-8")) > settings.THREAT_INTEL_MAX_IMPORT_BYTES:
        raise ValueError("blocklist payload exceeds the configured size limit")
    if actor_user_id is not None:
        actor = db_session.get(User, actor_user_id)
        if actor is None or actor.role != UserRole.ADMIN or not actor.is_active:
            raise PermissionError("administrator permission required")

    entries = _parse_import(payload, format)
    addresses = _validate_import_entries(db_session, entries)
    imported = 0
    for address in addresses:
        existing = (
            db_session.execute(
                select(ThreatBlocklistEntry).where(
                    ThreatBlocklistEntry.ip_address == address
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            continue
        db_session.add(
            ThreatBlocklistEntry(
                ip_address=address,
                source=source[:64],
                reason="imported indicator",
                created_by_user_id=actor_user_id,
            )
        )
        imported += 1
    db_session.flush()
    return {"received": len(addresses), "imported": imported}


def export_blocklist(
    db_session: Session, *, format: Literal["csv", "json"] = "json"
) -> str:
    """Export validated local indicators as CSV or JSON."""

    rows = (
        db_session.execute(
            select(ThreatBlocklistEntry).order_by(ThreatBlocklistEntry.ip_address)
        )
        .scalars()
        .all()
    )
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip_address", "source", "reason"])
        for row in rows:
            writer.writerow([row.ip_address, row.source, row.reason or ""])
        return output.getvalue()
    return json.dumps(
        [
            {
                "ip_address": row.ip_address,
                "source": row.source,
                "reason": row.reason,
            }
            for row in rows
        ],
        sort_keys=True,
    )


def ip_is_in_blocklist(db_session: Session, ip: str) -> bool:
    """Return True when an IP is present in the imported local blocklist."""

    try:
        address = str(parse_ip(ip))
    except ValueError:
        return False
    return (
        db_session.execute(
            select(ThreatBlocklistEntry).where(
                ThreatBlocklistEntry.ip_address == address
            )
        )
        .scalars()
        .first()
        is not None
    )


def prune_expired_cache(*, now: float | None = None) -> int:
    """Remove expired cache entries and return the number pruned."""

    moment = time.time() if now is None else now
    with _cache_lock:
        expired = [
            key
            for key, entry in _enrichment_cache.items()
            if entry.expires_at <= moment
        ]
        for key in expired:
            _enrichment_cache.pop(key, None)
    return len(expired)


def cache_size() -> int:
    """Return the current number of cached enrichment results."""

    with _cache_lock:
        return len(_enrichment_cache)

"""On-disk, versioned model registry.

Only this module moves directories. ``staging`` is written by training; a model
becomes ``active`` exclusively through an explicit, audited service-layer call.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from core.logging import get_logger
from ml.registry.errors import ChecksumError, RegistryError
from ml.registry.paths import (
    AREAS,
    artifact_path,
    ensure_registry_tree,
    registry_root,
    validate_filename,
    validate_version,
    version_directory,
)

logger = get_logger(__name__)

CHECKSUMS_FILE = "checksums.json"
METADATA_FILE = "metadata.json"
ACTIVE_POINTER = "active.json"
REQUIRED_ARTIFACTS: tuple[str, ...] = (
    "model.joblib",
    "scaler.joblib",
    "encoder.joblib",
    "isolation_forest.joblib",
    "features.json",
    "config.json",
    "baseline.json",
    "metrics.json",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8"
    )
    temporary.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read registry metadata: {path.name}") from exc
    if not isinstance(payload, dict):
        raise RegistryError(f"registry metadata must be an object: {path.name}")
    return payload


def stage_version(
    version: str,
    artifact_sources: dict[str, Path],
    metadata: dict[str, Any],
    root: Path | str | None = None,
) -> dict[str, str]:
    """Copy artifacts into staging and seal them with SHA-256 checksums."""

    safe_version = validate_version(version)
    base = ensure_registry_tree(root)
    destination = version_directory(safe_version, base, area="staging", create=True)
    if any(destination.iterdir()):
        raise RegistryError(f"staging version already exists: {safe_version}")

    checksums: dict[str, str] = {}
    for filename, source in artifact_sources.items():
        safe_name = validate_filename(filename)
        source_path = Path(source)
        if not source_path.is_file():
            raise RegistryError(f"artifact not found: {safe_name}")
        target = artifact_path(safe_version, safe_name, base, area="staging")
        shutil.copyfile(source_path, target)
        checksums[safe_name] = sha256_file(target)

    missing = sorted(set(REQUIRED_ARTIFACTS).difference(checksums))
    if missing:
        raise RegistryError(f"missing required artifacts: {', '.join(missing)}")
    _write_json(destination / CHECKSUMS_FILE, checksums)
    _write_json(destination / METADATA_FILE, metadata)
    logger.info("Staged model version %s under %s", safe_version, destination)
    return checksums


def verify_artifacts(
    version: str, root: Path | str | None = None, *, area: str = "staging"
) -> dict[str, str]:
    """Verify every artifact digest before any joblib file is deserialised."""

    safe_version = validate_version(version)
    base = registry_root(root)
    directory = version_directory(safe_version, base, area=area)
    checksums = _read_json(directory / CHECKSUMS_FILE)
    for filename, expected in checksums.items():
        path = artifact_path(safe_version, filename, base, area=area)
        if not path.is_file():
            raise ChecksumError(f"missing artifact: {filename}")
        if not isinstance(expected, str) or sha256_file(path) != expected:
            raise ChecksumError(f"checksum mismatch for artifact: {filename}")
    return {str(k): str(v) for k, v in checksums.items()}


def read_metadata(
    version: str, root: Path | str | None = None, *, area: str = "staging"
) -> dict[str, Any]:
    return _read_json(version_directory(version, root, area=area) / METADATA_FILE)


def active_version(root: Path | str | None = None) -> str | None:
    base = registry_root(root)
    pointer = base / ACTIVE_POINTER
    if not pointer.is_file():
        return None
    payload = _read_json(pointer)
    version = payload.get("version")
    return validate_version(version) if isinstance(version, str) else None


def _write_active_pointer(base: Path, version: str) -> None:
    _write_json(base / ACTIVE_POINTER, {"version": validate_version(version)})


def list_disk_versions(root: Path | str | None = None) -> dict[str, list[str]]:
    base = registry_root(root)
    found: dict[str, list[str]] = {}
    for area in AREAS:
        directory = base / area
        if not directory.is_dir():
            continue
        for child in directory.iterdir():
            if child.is_dir():
                try:
                    version = validate_version(child.name)
                except RegistryError:
                    continue
                found.setdefault(version, []).append(area)
    return {version: sorted(areas) for version, areas in sorted(found.items())}


def promote_version(
    version: str, root: Path | str | None = None
) -> tuple[str | None, str]:
    """Move a verified staged version to active; archive any previous active."""

    safe_version = validate_version(version)
    base = ensure_registry_tree(root)
    verify_artifacts(safe_version, base, area="staging")
    staging = version_directory(safe_version, base, area="staging")
    active_root = base / "active"
    previous = active_version(base)
    if previous and version_directory(previous, base, area="active").exists():
        old_active = version_directory(previous, base, area="active")
        archive = version_directory(previous, base, area="archive", create=True)
        if archive.exists():
            shutil.rmtree(archive)
        shutil.move(str(old_active), str(archive))
    target = active_root / safe_version
    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(staging), str(target))
    _write_active_pointer(base, safe_version)
    logger.info("Promoted model version %s to active", safe_version)
    return previous, safe_version


def rollback_version(
    root: Path | str | None = None, target_version: str | None = None
) -> tuple[str | None, str]:
    """Restore an archived version to active. No staging version is eligible."""

    base = ensure_registry_tree(root)
    archive_root = base / "archive"
    if target_version is None:
        candidates = (
            [p for p in archive_root.iterdir() if p.is_dir()]
            if archive_root.exists()
            else []
        )
        if not candidates:
            raise RegistryError("no archived version available for rollback")
        target_version = max(candidates, key=lambda p: p.stat().st_mtime).name
    safe_target = validate_version(target_version)
    verify_artifacts(safe_target, base, area="archive")

    previous = active_version(base)
    if previous and version_directory(previous, base, area="active").exists():
        old_active = version_directory(previous, base, area="active")
        archive = version_directory(previous, base, area="archive", create=True)
        if archive.exists():
            shutil.rmtree(archive)
        shutil.move(str(old_active), str(archive))

    source = version_directory(safe_target, base, area="archive")
    target = base / "active" / safe_target
    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(source), str(target))
    _write_active_pointer(base, safe_target)
    logger.info("Rolled back active model to version %s", safe_target)
    return previous, safe_target

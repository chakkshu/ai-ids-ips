"""Path validation and permission helpers for the on-disk model registry."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from core.config import settings

VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
AREAS = ("staging", "active", "archive")


class RegistryPathError(ValueError):
    """Raised when a version or filename could escape the registry root."""


def validate_version(version: str) -> str:
    """Reject traversal, separators, and unexpectedly long/invalid versions."""

    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise RegistryPathError(f"invalid model version: {version!r}")
    if ".." in version or version in {".", ".."}:
        raise RegistryPathError(f"invalid model version: {version!r}")
    return version


def validate_filename(filename: str) -> str:
    """Allow only flat, safe artifact names."""

    if not isinstance(filename, str) or not FILENAME_RE.fullmatch(filename):
        raise RegistryPathError(f"invalid artifact filename: {filename!r}")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise RegistryPathError(f"invalid artifact filename: {filename!r}")
    return filename


def registry_root(root: Path | str | None = None) -> Path:
    """Return the configured registry root as an absolute path."""

    return Path(root or settings.ML_MODEL_REGISTRY_PATH).expanduser().resolve()


def ensure_registry_tree(root: Path | str | None = None) -> Path:
    """Create staging/active/archive directories with owner-only permissions."""

    base = registry_root(root)
    for directory in (base, *(base / area for area in AREAS)):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        _harden_directory(directory)
    return base


def _harden_directory(directory: Path) -> None:
    """Best-effort 0700 on POSIX; Windows ACLs are left to the OS."""

    if os.name == "nt":
        return
    try:
        directory.chmod(stat.S_IRWXU)
    except OSError:  # pragma: no cover - platform dependent
        pass


def area_directory(root: Path | str | None, area: str, *, create: bool = False) -> Path:
    """Return a validated area directory inside the registry root."""

    if area not in AREAS:
        raise RegistryPathError(f"invalid registry area: {area!r}")
    base = registry_root(root)
    directory = (base / area).resolve()
    if directory.parent != base:
        raise RegistryPathError("registry area escapes the configured root")
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        _harden_directory(directory)
    return directory


def version_directory(
    version: str,
    root: Path | str | None = None,
    *,
    area: str = "staging",
    create: bool = False,
) -> Path:
    """Resolve ``<root>/<area>/<version>`` and reject traversal attempts."""

    safe_version = validate_version(version)
    directory = (area_directory(root, area, create=create) / safe_version).resolve()
    if directory.parent != area_directory(root, area):
        raise RegistryPathError("model version path escapes its registry area")
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        _harden_directory(directory)
    return directory


def artifact_path(
    version: str,
    filename: str,
    root: Path | str | None = None,
    *,
    area: str = "staging",
) -> Path:
    """Resolve a flat artifact filename under a validated version directory."""

    safe_name = validate_filename(filename)
    version_dir = version_directory(version, root, area=area)
    path = (version_dir / safe_name).resolve()
    if path.parent != version_dir:
        raise RegistryPathError("artifact path escapes its version directory")
    return path

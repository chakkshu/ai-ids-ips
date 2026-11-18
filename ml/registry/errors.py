"""Registry-specific exceptions."""

from __future__ import annotations


class RegistryError(RuntimeError):
    """Base class for registry failures."""


class ChecksumError(RegistryError):
    """An artifact was missing, tampered with, or has a mismatched digest."""

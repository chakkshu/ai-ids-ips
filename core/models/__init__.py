"""AI-IDS/IPS Models Package.

Exports all SQLAlchemy 2.0 ORM models for unified registry and migration discovery.
"""

from core.db import Base
from core.models.alert import Alert, AlertSeverity, AlertStatus
from core.models.audit import GENESIS_HASH, AuditLog
from core.models.detection import Detection
from core.models.mlops import AnalystFeedback, DriftMetric, ModelArtifact
from core.models.network import NetworkFlow
from core.models.prevention import BlockedIP, BlockStatus, Whitelist
from core.models.user import (
    APIKey,
    PasswordHistory,
    RecoveryCode,
    User,
    UserRole,
    UserSession,
)

__all__ = [
    "GENESIS_HASH",
    "APIKey",
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "AnalystFeedback",
    "AuditLog",
    "Base",
    "BlockStatus",
    "BlockedIP",
    "Detection",
    "DriftMetric",
    "ModelArtifact",
    "NetworkFlow",
    "PasswordHistory",
    "RecoveryCode",
    "User",
    "UserRole",
    "UserSession",
    "Whitelist",
]

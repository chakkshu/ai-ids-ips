"""AI-IDS/IPS Models Package.

Exports all SQLAlchemy 2.0 ORM models for unified registry and migration discovery.
"""

from core.db import Base
from core.models.alert import (
    Alert,
    AlertComment,
    AlertEscalationRule,
    AlertSeverity,
    AlertStatus,
    Notification,
    NotificationChannel,
    NotificationStatus,
)
from core.models.audit import GENESIS_HASH, AuditLog
from core.models.detection import Detection
from core.models.mlops import AnalystFeedback, DriftMetric, ModelArtifact
from core.models.network import NetworkFlow
from core.models.prevention import (
    BlockedIP,
    BlockStatus,
    DecisionAction,
    PolicyConfig,
    PreventionAction,
    PreventionActionType,
    PreventionCandidate,
    PreventionDecision,
    Whitelist,
)
from core.models.threat import IPProfile, ThreatBlocklistEntry
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
    "AlertComment",
    "AlertEscalationRule",
    "AlertSeverity",
    "AlertStatus",
    "AnalystFeedback",
    "AuditLog",
    "Base",
    "BlockStatus",
    "BlockedIP",
    "DecisionAction",
    "Detection",
    "DriftMetric",
    "IPProfile",
    "ModelArtifact",
    "NetworkFlow",
    "Notification",
    "NotificationChannel",
    "NotificationStatus",
    "PasswordHistory",
    "PolicyConfig",
    "PreventionAction",
    "PreventionActionType",
    "PreventionCandidate",
    "PreventionDecision",
    "RecoveryCode",
    "ThreatBlocklistEntry",
    "User",
    "UserRole",
    "UserSession",
    "Whitelist",
]

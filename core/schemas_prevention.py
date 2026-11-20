"""Strict request schemas for Phase 6 prevention, alerting, and intel APIs."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.models.alert import AlertStatus


class StrictModel(BaseModel):
    """Reject unknown fields and normalize string whitespace."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("a valid IP address is required") from exc


def _validate_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("a valid IP network is required") from exc
    if network.prefixlen == 0:
        raise ValueError("a /0 network is not permitted")
    return str(network)


class BlockCreate(StrictModel):
    """Payload for a manual temporary block."""

    ip_address: str = Field(min_length=1, max_length=45)
    reason: str = Field(min_length=1, max_length=255)
    duration_minutes: int | None = Field(default=None, ge=1, le=10080)

    @field_validator("ip_address")
    @classmethod
    def ip(cls, value: str) -> str:
        return _validate_ip(value)


class BlockExtend(StrictModel):
    """Payload for extending an active block."""

    additional_minutes: int = Field(ge=1, le=10080)


class WhitelistCreate(StrictModel):
    """Payload for adding a protected CIDR."""

    cidr: str = Field(min_length=1, max_length=45)
    description: str = Field(min_length=1, max_length=255)

    @field_validator("cidr")
    @classmethod
    def cidr_value(cls, value: str) -> str:
        return _validate_cidr(value)


class ApprovalDecision(StrictModel):
    """Optional rationale for approving or rejecting a pending block."""

    reason: str | None = Field(default=None, max_length=255)


class PolicyUpdate(StrictModel):
    """Partial update to the active prevention policy."""

    confidence_threshold: float | None = Field(default=None, ge=0.5, le=1.0)
    min_detections: int | None = Field(default=None, ge=2)
    window_seconds: int | None = Field(default=None, ge=1)
    severity_mapping: dict[str, str] | None = None
    class_actions: dict[str, str] | None = None
    block_duration_minutes: int | None = Field(default=None, ge=1)
    escalation_ladder_minutes: list[int] | None = None
    approval_mode: bool | None = None
    kill_switch: bool | None = None
    rare_classes: list[str] | None = None

    @field_validator("severity_mapping")
    @classmethod
    def severities(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is not None and any(
            severity not in {"low", "medium", "high", "critical"}
            for severity in value.values()
        ):
            raise ValueError("invalid severity value")
        return value

    @field_validator("class_actions")
    @classmethod
    def actions(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is not None and any(
            action not in {"block", "alert_only", "no_action"}
            for action in value.values()
        ):
            raise ValueError("invalid class action")
        return value

    @field_validator("escalation_ladder_minutes")
    @classmethod
    def ladder(cls, value: list[int] | None) -> list[int] | None:
        if value is not None and (not value or any(item <= 0 for item in value)):
            raise ValueError("escalation ladder must contain positive durations")
        return value


class AlertStatusUpdate(StrictModel):
    """Lifecycle transition request."""

    status: AlertStatus
    notes: str | None = Field(default=None, max_length=4000)


class AlertAssign(StrictModel):
    """Assignment request for an analyst."""

    user_id: int = Field(ge=1)


class AlertCommentCreate(StrictModel):
    """Analyst triage comment."""

    comment: str = Field(min_length=1, max_length=4000)


class AlertFeedbackCreate(StrictModel):
    """Ground-truth feedback for future retraining only."""

    is_false_positive: bool
    verified_label: str = Field(min_length=1, max_length=64)
    notes: str | None = Field(default=None, max_length=4000)


class ThreatIntelRequest(StrictModel):
    """Enrichment request using one of the fixed provider identifiers."""

    ip_address: str = Field(min_length=1, max_length=45)
    provider: Literal["abuseipdb", "virustotal"] = "abuseipdb"

    @field_validator("ip_address")
    @classmethod
    def ip(cls, value: str) -> str:
        return _validate_ip(value)


class BlocklistImport(StrictModel):
    """Bounded CSV or JSON blocklist import payload."""

    format: Literal["csv", "json"]
    payload: str = Field(min_length=1)
    source: str = Field(default="operator-import", max_length=64)


class KeyRotateRequest(StrictModel):
    """Rotate request; secret key material is supplied via environment only."""

    key_id: str = Field(min_length=1, max_length=32)
    kek_env_var: str = Field(default="AI_IDS_NEW_KEK", max_length=64)
    activate: bool = True


class KeyRewrapRequest(StrictModel):
    """Re-encryption request for the audited, resumable rewrap job."""

    target_key_id: str = Field(min_length=1, max_length=32)
    batch_size: int = Field(default=100, ge=1, le=1000)

"""AI-IDS/IPS Structured Logging Module.

Provides JSON-formatted structured logging, contextual correlation IDs,
sensitive field redaction, and CEF/Syslog export for SIEM systems.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

# Context variable for request correlation tracking
correlation_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)

SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "kek",
    "app_master_kek",
    "audit_hmac_secret",
    "authorization",
}


def get_correlation_id() -> str:
    """Retrieve current correlation ID or generate a new one if unset."""
    cid = correlation_id_ctx.get()
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id_ctx.set(cid)
    return cid


def set_correlation_id(cid: str | None = None) -> str:
    """Explicitly set or generate correlation ID in context."""
    final_cid = cid or str(uuid.uuid4())
    correlation_id_ctx.set(final_cid)
    return final_cid


def redact_sensitive_data(data: Any) -> Any:
    """Recursively mask sensitive values in dictionaries and lists."""
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            if any(sensitive in k.lower() for sensitive in SENSITIVE_KEYS):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_data(v)
        return redacted
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    return data


class CorrelationIdFilter(logging.Filter):
    """Ensures every log record contains a valid correlation_id attribute."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id") or not record.correlation_id:
            record.correlation_id = get_correlation_id()
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects with ISO 8601 timestamps and correlation IDs."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", get_correlation_id()),
            "module": record.module,
            "line": record.lineno,
            "process_id": os.getpid(),
        }

        # Include custom extra metadata if present
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_payload["data"] = redact_sensitive_data(record.extra_data)

        # Include exception trace if present
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload)


class CEFFormatter(logging.Formatter):
    """Formats security events into ArcSight Common Event Format (CEF) for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        severity_map = {
            "DEBUG": "1",
            "INFO": "3",
            "WARNING": "6",
            "ERROR": "8",
            "CRITICAL": "10",
        }
        cef_sev = severity_map.get(record.levelname, "3")
        device_vendor = "AI-IDS-IPS"
        device_product = "EnterpriseDefense"
        device_version = "1.0.0"
        event_class_id = getattr(record, "event_type", "SECURITY_EVENT")
        event_name = record.getMessage()

        extension_pairs = [
            f"cid={getattr(record, 'correlation_id', get_correlation_id())}",
            f"logger={record.name}",
        ]

        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            clean_data = redact_sensitive_data(record.extra_data)
            for k, v in clean_data.items():
                extension_pairs.append(f"{k}={v}")

        extension_str = " ".join(extension_pairs)
        return f"CEF:0|{device_vendor}|{device_product}|{device_version}|{event_class_id}|{event_name}|{cef_sev}|{extension_str}"


def setup_logging(
    level: str = "INFO",
    json_format: bool = True,
    cef_export_path: str | None = None,
) -> logging.Logger:
    """Configure root logger with console and optional CEF file handlers."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.addFilter(CorrelationIdFilter())
    if json_format:
        console_handler.setFormatter(StructuredJsonFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] [CID:%(correlation_id)s]: %(message)s"
            )
        )
    root_logger.addHandler(console_handler)

    if cef_export_path:
        cef_dir = os.path.dirname(cef_export_path)
        if cef_dir:
            os.makedirs(cef_dir, exist_ok=True)
        cef_handler = logging.FileHandler(cef_export_path)
        cef_handler.setFormatter(CEFFormatter())
        root_logger.addHandler(cef_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Convenience factory returning a named logger."""
    return logging.getLogger(name)

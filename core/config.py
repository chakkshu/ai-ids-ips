"""AI-IDS/IPS Core Configuration Module.

Uses Pydantic BaseSettings for strict environment variable parsing, type enforcement,
and security validations.
"""

from __future__ import annotations

import ipaddress
import secrets
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Central application settings validated against environment variables."""

    # Application Lifecycle
    APP_NAME: str = "AI-IDS/IPS Enterprise Defensive Platform"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "testing", "production"] = "development"
    APP_DEBUG: bool = False
    APP_SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        description="Flask session signing key",
    )

    # Cryptography & Master Keys (Envelope Encryption)
    APP_MASTER_KEK: str = Field(
        default="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        description="32-byte hexadecimal Key Encryption Key for AES-256-GCM envelope encryption",
    )
    APP_KEK_VERSION: str = "v1"
    AUDIT_HMAC_SECRET: str = Field(
        default="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        description="Secret key used for HMAC-SHA256 audit ledger hash chaining",
    )

    # Database Settings (PostgreSQL 16)
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "ai_ids_ips"
    DB_USER: str = "ids_admin"
    DB_PASSWORD: str = "ids_secure_password_replace_in_prod"
    DATABASE_URL: str | None = None

    # Redis Broker & Cache Settings
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    REDIS_DB: int = 0
    REDIS_URL: str | None = None

    # Network Packet Capture (Sensor) Settings
    SENSOR_INTERFACE: str = "auto"
    SENSOR_BPF_FILTER: str = "ip"
    SENSOR_FLOW_TIMEOUT_ACTIVE: int = 120  # seconds
    SENSOR_FLOW_TIMEOUT_IDLE: int = 30     # seconds
    SENSOR_SIMULATION_MODE: bool = True

    # Prevention Engine Settings
    PREVENTION_MODE: Literal["dry_run", "active"] = "dry_run"
    PREVENTION_REQUIRE_APPROVAL: bool = False
    PREVENTION_CONFIDENCE_THRESHOLD: float = 0.85
    PREVENTION_MIN_DETECTIONS: int = 2
    PREVENTION_WINDOW_SECONDS: int = 60
    PREVENTION_BLOCK_DURATION_MINUTES: int = 15
    PREVENTION_WHITELIST: str = "127.0.0.1/32,::1/128,192.168.1.1/32,10.0.0.1/32"

    # Machine Learning & MLOps
    ML_MODEL_REGISTRY_PATH: str = str(BASE_DIR / "ml" / "registry")
    ML_ACTIVE_MODEL_VERSION: str = "1.0.0"
    ML_DRIFT_THRESHOLD_PSI: float = 0.25

    # Threat Intelligence Integrations
    ABUSEIPDB_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    GEOIP_DATABASE_PATH: str | None = None

    # Alerting & Notifications
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_USE_TLS: bool = True
    ALERT_FROM_EMAIL: str = "alerts@ai-ids-ips.local"
    ALERT_NOTIFICATION_EMAIL: str | None = None
    SLACK_WEBHOOK_URL: str | None = None
    TEAMS_WEBHOOK_URL: str | None = None

    # Initial Admin Account Seed
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_EMAIL: str = "admin@ai-ids-ips.local"
    INITIAL_ADMIN_PASSWORD: str = "ChangeMeOnFirstLogin123!"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    @field_validator("APP_MASTER_KEK")
    @classmethod
    def validate_kek(cls, v: str) -> str:
        """Validate KEK is valid 32-byte hex string (64 characters)."""
        clean_v = v.strip()
        if len(clean_v) != 64:
            raise ValueError("APP_MASTER_KEK must be exactly 64 hex characters (32 bytes)")
        try:
            bytes.fromhex(clean_v)
        except ValueError as exc:
            raise ValueError("APP_MASTER_KEK must be valid hexadecimal") from exc
        return clean_v

    @field_validator("PREVENTION_CONFIDENCE_THRESHOLD")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence threshold is between 0.50 and 1.00."""
        if not (0.5 <= v <= 1.0):
            raise ValueError("PREVENTION_CONFIDENCE_THRESHOLD must be between 0.5 and 1.0")
        return v

    def get_database_url(self) -> str:
        """Return canonical database URL."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    def get_redis_url(self) -> str:
        """Return canonical Redis connection URL."""
        if self.REDIS_URL:
            return self.REDIS_URL
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    def get_parsed_whitelist(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse comma-separated CIDR strings into validated IP network objects."""
        networks = []
        raw_entries = [entry.strip() for entry in self.PREVENTION_WHITELIST.split(",") if entry.strip()]
        for entry in raw_entries:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                networks.append(net)
            except ValueError:
                continue
        return networks


# Global cached settings instance
settings = Settings()

"""AI-IDS/IPS Core Configuration Module.

Uses Pydantic BaseSettings for strict environment variable parsing, type enforcement,
and security validations.
"""

from __future__ import annotations

import ipaddress
import secrets
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
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
    # JSON object mapping retired/current key IDs to 32-byte hex KEKs, e.g.
    # '{"v1":"<64 hex>","v2":"<64 hex>"}'. Secrets are never logged.
    APP_KEK_REGISTRY: str = "{}"
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

    # Redis Stream Contract (Phase 5)
    # ``raw-flows`` is the sensor -> detection-engine ingress. The detection
    # and prevention streams are publish-only in this phase; no firewall
    # action is implemented.
    STREAM_RAW_FLOWS: str = "raw-flows"
    STREAM_DETECTIONS: str = "detections:stream"
    STREAM_PREVENTION: str = "prevention:action"
    STREAM_DEAD_LETTER: str = "raw-flows:dead-letter"
    STREAM_DETECTIONS_DEAD_LETTER: str = "detections:stream:dead-letter"
    STREAM_CONSUMER_GROUP: str = "detection-engine"
    STREAM_CONSUMER_NAME: str = "detection-worker-1"
    STREAM_PREVENTION_CONSUMER_GROUP: str = "prevention-engine"
    STREAM_PREVENTION_CONSUMER_NAME: str = "prevention-worker-1"
    STREAM_PREVENTION_DEAD_LETTER: str = "prevention:action:dead-letter"
    STREAM_BATCH_SIZE: int = 32
    STREAM_BLOCK_MS: int = 1000
    STREAM_MAXLEN: int = 10000
    STREAM_MAX_PENDING: int = 512
    STREAM_MAX_ATTEMPTS: int = 3

    # Network Packet Capture (Sensor) Settings
    SENSOR_INTERFACE: str = "auto"
    SENSOR_BPF_FILTER: str = "ip"
    SENSOR_FLOW_TIMEOUT_ACTIVE: int = 120  # seconds
    SENSOR_FLOW_TIMEOUT_IDLE: int = 30  # seconds
    SENSOR_SIMULATION_MODE: bool = True
    # Optional canonical toggle. When unset, SENSOR_SIMULATION_MODE wins so
    # the Phase 1 setting remains a valid live/simulation switch.
    CAPTURE_MODE: Literal["live", "simulation"] | None = None

    # Prevention Engine Settings
    PREVENTION_MODE: Literal["dry_run", "active"] = "dry_run"
    # Real firewall changes require BOTH ``PREVENTION_MODE=active`` and this
    # explicit opt-in, and are always forced back to dry-run in simulation mode.
    PREVENTION_ALLOW_REAL_ENFORCEMENT: bool = False
    PREVENTION_KILL_SWITCH: bool = False
    PREVENTION_REQUIRE_APPROVAL: bool = False
    PREVENTION_CONFIDENCE_THRESHOLD: float = 0.85
    PREVENTION_MIN_DETECTIONS: int = 2
    PREVENTION_WINDOW_SECONDS: int = 60
    PREVENTION_BLOCK_DURATION_MINUTES: int = 15
    PREVENTION_WHITELIST: str = "127.0.0.1/32,::1/128,192.168.1.1/32,10.0.0.1/32"
    PREVENTION_PROTECTED_CIDRS: str = ""
    PREVENTION_DEFAULT_GATEWAYS: str = ""
    PREVENTION_ADMIN_IP: str | None = None
    PREVENTION_DNS_SERVERS: str = ""
    PREVENTION_RARE_CLASSES: str = (
        "Heartbleed,Infiltration,SQL Injection,Web Attack - Sql Injection"
    )
    PREVENTION_ESCALATION_LADDER_MINUTES: str = "15,60,240,1440"

    # Machine Learning & MLOps
    ML_MODEL_REGISTRY_PATH: str = str(BASE_DIR / "ml" / "registry")
    ML_ACTIVE_MODEL_VERSION: str = "1.0.0"
    ML_DRIFT_THRESHOLD_PSI: float = 0.25
    ML_DRIFT_CRITICAL_PSI: float = 0.5
    ML_DRIFT_P_VALUE_THRESHOLD: float = 0.05
    ML_RANDOM_SEED: int = 42
    ML_CONFIDENCE_THRESHOLD: float = 0.70
    ML_ANOMALY_SCORE_THRESHOLD: float = 0.60
    ML_DATASET_DIR: str = str(BASE_DIR / "data" / "raw")

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
    ALERT_NOTIFICATION_MAX_ATTEMPTS: int = 3
    ALERT_NOTIFICATION_RETRY_SECONDS: float = 2.0
    ALERT_WEBHOOK_TIMEOUT_SECONDS: float = 3.0

    # Threat Intelligence Settings (external providers are OFF unless a key
    # and an explicit provider hostname are configured).
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 3600
    THREAT_INTEL_TIMEOUT_SECONDS: float = 3.0
    THREAT_INTEL_MAX_IMPORT_BYTES: int = 1_048_576

    # Password Hashing (Argon2id) - explicit, tunable parameters
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536  # KiB (64 MiB)
    ARGON2_PARALLELISM: int = 4
    ARGON2_HASH_LEN: int = 32
    ARGON2_SALT_LEN: int = 16

    # Password Policy
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_HISTORY_DEPTH: int = 5

    # Account Lockout & Login Throttling
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Server-side Session Policy
    SESSION_IDLE_TIMEOUT_MINUTES: int = 30
    SESSION_ABSOLUTE_TIMEOUT_HOURS: int = 8
    SESSION_COOKIE_SAMESITE: Literal["Lax", "Strict"] = "Strict"

    # Trusted reverse proxy handling. Set to the exact number of proxies in
    # front of the application (0 disables X-Forwarded-* trust entirely).
    TRUSTED_PROXY_HOPS: int = 0

    # Rate limiting backend. Production must use Redis; dev/test use memory.
    RATELIMIT_STORAGE_URI: str | None = None

    # TOTP / Recovery Codes
    TOTP_ISSUER: str = "AI-IDS-IPS-SOC"
    TOTP_VALID_WINDOW: int = 1
    RECOVERY_CODE_COUNT: int = 10

    # Socket.IO browser origins. Empty means same-origin only.
    SOCKETIO_ALLOWED_ORIGINS: str = ""

    # Initial Admin Account Seed
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_EMAIL: str = "admin@ai-ids-ips.local"
    INITIAL_ADMIN_PASSWORD: str = "ChangeMeOnFirstLogin123!"
    INITIAL_ADMIN_FORCE_PASSWORD_CHANGE: bool = True

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
            raise ValueError(
                "APP_MASTER_KEK must be exactly 64 hex characters (32 bytes)"
            )
        try:
            bytes.fromhex(clean_v)
        except ValueError as exc:
            raise ValueError("APP_MASTER_KEK must be valid hexadecimal") from exc
        return clean_v

    @model_validator(mode="after")
    def reconcile_capture_mode(self) -> Settings:
        """Keep the legacy boolean and canonical mode toggle consistent."""

        if self.CAPTURE_MODE is None:
            mode = "simulation" if self.SENSOR_SIMULATION_MODE else "live"
            object.__setattr__(self, "CAPTURE_MODE", mode)
        else:
            object.__setattr__(
                self, "SENSOR_SIMULATION_MODE", self.CAPTURE_MODE == "simulation"
            )
        return self

    @field_validator(
        "STREAM_BATCH_SIZE",
        "STREAM_MAXLEN",
        "STREAM_MAX_PENDING",
        "STREAM_MAX_ATTEMPTS",
    )
    @classmethod
    def validate_stream_limits(cls, v: int) -> int:
        """Reject zero or negative stream/backpressure limits."""

        if v <= 0:
            raise ValueError("Stream limits must be positive integers")
        return v

    @field_validator("STREAM_BLOCK_MS")
    @classmethod
    def validate_stream_block(cls, v: int) -> int:
        """Allow block=0 (non-blocking reads) but reject negative waits."""

        if v < 0:
            raise ValueError("STREAM_BLOCK_MS must be zero or greater")
        return v

    @field_validator("PREVENTION_CONFIDENCE_THRESHOLD")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence threshold is between 0.50 and 1.00."""
        if not (0.5 <= v <= 1.0):
            raise ValueError(
                "PREVENTION_CONFIDENCE_THRESHOLD must be between 0.5 and 1.0"
            )
        return v

    @field_validator("PREVENTION_MIN_DETECTIONS")
    @classmethod
    def validate_min_detections(cls, v: int) -> int:
        """A single prediction must never be enough to trigger a block."""

        if v < 2:
            raise ValueError("PREVENTION_MIN_DETECTIONS must be at least 2")
        return v

    @field_validator(
        "PREVENTION_WINDOW_SECONDS",
        "PREVENTION_BLOCK_DURATION_MINUTES",
        "ALERT_NOTIFICATION_MAX_ATTEMPTS",
        "THREAT_INTEL_CACHE_TTL_SECONDS",
        "THREAT_INTEL_MAX_IMPORT_BYTES",
    )
    @classmethod
    def validate_prevention_positive_int(cls, v: int) -> int:
        """Reject non-positive prevention, alerting, and intel limits."""

        if v <= 0:
            raise ValueError("Prevention and alerting limits must be positive")
        return v

    @field_validator(
        "ARGON2_TIME_COST",
        "ARGON2_MEMORY_COST",
        "ARGON2_PARALLELISM",
        "ARGON2_HASH_LEN",
        "ARGON2_SALT_LEN",
        "PASSWORD_MIN_LENGTH",
        "PASSWORD_HISTORY_DEPTH",
        "LOGIN_MAX_ATTEMPTS",
        "LOGIN_LOCKOUT_MINUTES",
        "SESSION_IDLE_TIMEOUT_MINUTES",
        "SESSION_ABSOLUTE_TIMEOUT_HOURS",
        "TOTP_VALID_WINDOW",
        "RECOVERY_CODE_COUNT",
        "ML_RANDOM_SEED",
        "SENSOR_FLOW_TIMEOUT_ACTIVE",
        "SENSOR_FLOW_TIMEOUT_IDLE",
    )
    @classmethod
    def validate_positive_int(cls, v: int) -> int:
        """Reject non-positive security parameters."""
        if v <= 0:
            raise ValueError("Security parameters must be positive integers")
        return v

    @field_validator("TRUSTED_PROXY_HOPS")
    @classmethod
    def validate_proxy_hops(cls, v: int) -> int:
        """Proxy hop count must be a non-negative integer."""
        if v < 0:
            raise ValueError("TRUSTED_PROXY_HOPS must be zero or greater")
        return v

    def get_capture_mode(self) -> Literal["live", "simulation"]:
        """Return the active capture mode from the Phase 1 settings."""

        mode = self.CAPTURE_MODE or (
            "simulation" if self.SENSOR_SIMULATION_MODE else "live"
        )
        return "simulation" if mode == "simulation" else "live"

    def is_simulation_mode(self) -> bool:
        """Return True when no live capture/firewall action may be performed."""

        return self.get_capture_mode() == "simulation"

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

    def get_rate_limit_storage_uri(self) -> str:
        """Return the Flask-Limiter storage backend.

        Production must use Redis so limits are shared across workers. Development
        and test environments use in-memory storage to avoid an external dependency.
        """
        if self.RATELIMIT_STORAGE_URI:
            return self.RATELIMIT_STORAGE_URI
        if self.APP_ENV == "production":
            return self.get_redis_url()
        return "memory://"

    def get_socketio_origins(self) -> list[str] | None:
        """Return explicit Socket.IO origins, or None to enforce same-origin only."""
        origins = [
            item.strip()
            for item in self.SOCKETIO_ALLOWED_ORIGINS.split(",")
            if item.strip()
        ]
        return origins or None

    def get_parsed_whitelist(
        self,
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse comma-separated CIDR strings into validated IP network objects."""
        networks = []
        raw_entries = [
            entry.strip()
            for entry in self.PREVENTION_WHITELIST.split(",")
            if entry.strip()
        ]
        for entry in raw_entries:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                networks.append(net)
            except ValueError:
                continue
        return networks


# Global cached settings instance
settings = Settings()

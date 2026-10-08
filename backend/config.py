"""
AI-SIEM Guardian — Configuration Module
Centralized configuration using environment variables with secure defaults.
"""

import os
import sys
import secrets
from typing import List
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "AI-SIEM Guardian"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # ── Database ─────────────────────────────────────────────────
    # Default: SQLite for local development; set DATABASE_URL for PostgreSQL
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./siem_guardian.db"
    )

    # ── JWT Authentication ───────────────────────────────────────
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))

    # ── CORS ─────────────────────────────────────────────────────
    # Default to localhost for development; must be explicitly set for production
    CORS_ORIGINS: List[str] = os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000,http://localhost:80"
    ).split(",")

    # ── SMTP Email Alerts ────────────────────────────────────────
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")

    # ── AI Engine ────────────────────────────────────────────────
    ANOMALY_CONTAMINATION: float = float(os.getenv("ANOMALY_CONTAMINATION", "0.1"))
    MIN_TRAINING_SAMPLES: int = int(os.getenv("MIN_TRAINING_SAMPLES", "20"))

    # ── Rate Limiting ────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
    LOGIN_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("LOGIN_RATE_LIMIT_PER_MINUTE", "5"))

    # ── Network Analyzer ─────────────────────────────────────────
    ENABLE_REAL_CAPTURE: bool = os.getenv("ENABLE_REAL_CAPTURE", "false").lower() == "true"
    CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "eth0")
    PACKET_COUNT: int = int(os.getenv("PACKET_COUNT", "100"))

    # ── Agent Configuration ──────────────────────────────────────
    AGENT_API_KEY: str = os.getenv("AGENT_API_KEY", "")

    # ── WebSocket ────────────────────────────────────────────────
    WS_HEARTBEAT_INTERVAL: int = int(os.getenv("WS_HEARTBEAT_INTERVAL", "30"))

    # ── Security Headers ─────────────────────────────────────────
    ENABLE_SECURITY_HEADERS: bool = os.getenv("ENABLE_SECURITY_HEADERS", "true").lower() == "true"

    # ── Session Management ───────────────────────────────────────
    SESSION_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
    MAX_SESSIONS_PER_USER: int = int(os.getenv("MAX_SESSIONS_PER_USER", "5"))

    # ── Logging ──────────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/siem_guardian.log")

    # ── Database Guardian ────────────────────────────────────────
    DB_MONITOR_HEALTH_INTERVAL: int = int(os.getenv("DB_MONITOR_HEALTH_INTERVAL", "300"))  # 5 minutes
    DB_MONITOR_LOGIN_INTERVAL: int = int(os.getenv("DB_MONITOR_LOGIN_INTERVAL", "60"))     # 60 seconds
    DB_MONITOR_QUERY_INTERVAL: int = int(os.getenv("DB_MONITOR_QUERY_INTERVAL", "60"))     # 1 minute
    # Secret provider for stored credentials. Validated at application startup
    # (secret_provider.validate_secret_provider); never auto-generated.
    SECRET_PROVIDER: str = os.getenv("SECRET_PROVIDER", "fernet")
    DB_ENCRYPTION_KEY: str = os.getenv("DB_ENCRYPTION_KEY", "")  # Fernet key for credentials
    DB_GUARDIAN_MONITORING_ENABLED: bool = os.getenv("DB_GUARDIAN_MONITORING_ENABLED", "true").lower() == "true"

    # ── SQL statement logging ────────────────────────────────────
    # Off by default even in DEBUG: echo logs bound parameters, which can
    # include password hashes and encrypted credentials.
    SQL_ECHO: bool = os.getenv("SQL_ECHO", "false").lower() == "true"

    def validate(self):
        """
        Validate critical configuration values at startup.
        Raises SystemExit if production security requirements are not met.
        """
        errors = []

        # Validate JWT secret key
        if not self.JWT_SECRET_KEY:
            if self.DEBUG:
                # Development mode: generate a temporary key and warn
                self.JWT_SECRET_KEY = secrets.token_urlsafe(32)
                print(
                    "WARNING: JWT_SECRET_KEY not set. Using temporary key for development.\n"
                    "   Generate a secure key with: python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
                    "   Add it to .env as: JWT_SECRET_KEY=<your-key>"
                )
            else:
                errors.append(
                    "JWT_SECRET_KEY is required in production mode. "
                    "Set DEBUG=false only after configuring all secrets."
                )

        # Validate JWT secret strength
        if len(self.JWT_SECRET_KEY) < 32:
            errors.append(
                "JWT_SECRET_KEY is too short ({} chars). ".format(len(self.JWT_SECRET_KEY)) +
                "Use at least 32 characters for security."
            )

        # Warn about database configuration in production
        if not self.DEBUG and self.DATABASE_URL.startswith("sqlite"):
            print(
                "WARNING: Using SQLite in production mode.\n"
                "   For production deployments, use PostgreSQL:\n"
                "   DATABASE_URL=postgresql://user:password@host:port/database"
            )

        # Validate CORS origins in production
        if not self.DEBUG:
            if "localhost" in ",".join(self.CORS_ORIGINS):
                print(
                    "WARNING: CORS_ORIGINS includes localhost in production mode.\n"
                    "   Update CORS_ORIGINS to include only production domains."
                )

        # Check agent API key
        if not self.AGENT_API_KEY and not self.DEBUG:
            print(
                "WARNING: AGENT_API_KEY not set in production mode.\n"
                "   Agents will not be able to authenticate."
            )

        if errors:
            print("\nERROR: CONFIGURATION ERRORS:")
            for error in errors:
                print("   • " + error)
            print("\n   Fix these issues in your .env file before starting in production mode.\n")
            sys.exit(1)


settings = Settings()
settings.validate()

"""
AI-SIEM Guardian — SQLAlchemy ORM Models
Tables: users, logs, alerts, network_activity, audit_logs
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, DateTime, Text, JSON, Enum as SAEnum
)
from database import Base
import enum


class UserRole(str, enum.Enum):
    """Supported user roles with hierarchical permissions."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.VIEWER.value, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String(50), nullable=True)
    ip = Column(String(45), nullable=False)
    event_type = Column(String(50), nullable=False)          # login, logout, error, security
    failed_attempts = Column(Integer, default=0)
    login_frequency = Column(Float, default=0.0)             # logins per hour
    ip_activity_rate = Column(Float, default=0.0)            # requests per minute from IP
    anomaly = Column(Boolean, default=False)
    raw_data = Column(Text, nullable=True)                   # original log JSON
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, nullable=True)                  # FK to originating log
    severity = Column(String(20), default="medium")          # low, medium, high, critical
    message = Column(Text, nullable=False)
    ip = Column(String(45), nullable=True)
    alert_type = Column(String(50), nullable=True)           # brute_force, anomaly, port_scan …
    acknowledged = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class NetworkActivity(Base):
    __tablename__ = "network_activity"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), nullable=False)
    packets = Column(Integer, default=0)
    bytes_transferred = Column(Integer, default=0)
    protocol = Column(String(20), nullable=True)
    suspicious = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


# ── Database Guardian Models ─────────────────────────────────────────────

class DatabaseAsset(Base):
    """Registered database for monitoring."""
    __tablename__ = "database_assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    db_type = Column(String(20), nullable=False)  # sqlite, postgresql, mysql, etc.
    host = Column(String(255), nullable=True)  # NULL for SQLite
    port = Column(Integer, nullable=True)
    database_name = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False)
    encrypted_password = Column(Text, nullable=False)  # Fernet encrypted
    is_active = Column(Boolean, default=True)
    last_check = Column(DateTime, nullable=True)
    status = Column(String(20), default="unknown")  # online, offline, error
    risk_score = Column(Integer, default=0)  # 0-100
    metadata_json = Column(Text, nullable=True)  # JSON: version, size, etc.
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class DatabaseHealthCheck(Base):
    """Health check results."""
    __tablename__ = "database_health_checks"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    check_time = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String(20), nullable=False)  # online, offline, degraded
    response_time_ms = Column(Integer, nullable=True)
    connection_count = Column(Integer, nullable=True)
    database_size_mb = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)


class DatabaseLoginEvent(Base):
    """Database login tracking."""
    __tablename__ = "database_login_events"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    username = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    auth_method = Column(String(50), nullable=True)
    connection_duration = Column(Integer, nullable=True)  # seconds


class DatabaseUser(Base):
    """Tracked database users and their privileges."""
    __tablename__ = "database_users"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    username = Column(String(100), nullable=False)
    is_admin = Column(Boolean, default=False)
    privileges_json = Column(Text, nullable=True)  # JSON list
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DatabasePrivilegeChange(Base):
    """Privilege change audit trail."""
    __tablename__ = "database_privilege_changes"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    target_user = Column(String(100), nullable=False)
    change_type = Column(String(50), nullable=False)  # grant, revoke, create_user, drop_user
    privilege = Column(String(100), nullable=True)
    granted_by = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class DatabaseQueryLog(Base):
    """Query activity tracking."""
    __tablename__ = "database_query_logs"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    username = Column(String(100), nullable=False)
    source_ip = Column(String(45), nullable=True)
    query_type = Column(String(20), nullable=False)  # SELECT, INSERT, UPDATE, DELETE, etc.
    table_name = Column(String(100), nullable=True)
    rows_affected = Column(Integer, nullable=True)
    execution_time_ms = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_sensitive = Column(Boolean, default=False)


class DatabaseSchemaChange(Base):
    """Schema change tracking."""
    __tablename__ = "database_schema_changes"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    change_type = Column(String(50), nullable=False)  # create_table, drop_table, alter_table, etc.
    object_type = Column(String(50), nullable=False)  # table, index, view, procedure
    object_name = Column(String(100), nullable=False)
    performed_by = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    details_json = Column(Text, nullable=True)


class DatabaseConfigChange(Base):
    """Configuration change tracking."""
    __tablename__ = "database_config_changes"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    parameter_name = Column(String(100), nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    changed_by = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class DatabaseBackup(Base):
    """Backup tracking."""
    __tablename__ = "database_backups"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    backup_time = Column(DateTime, nullable=False, index=True)
    backup_type = Column(String(20), nullable=False)  # full, incremental, differential
    backup_size_mb = Column(Integer, nullable=True)
    backup_location = Column(String(255), nullable=True)
    success = Column(Boolean, nullable=False)
    verification_status = Column(String(20), default="not_verified")  # not_verified, verified, failed
    error_message = Column(Text, nullable=True)


class DatabaseAlert(Base):
    """Database-specific alerts."""
    __tablename__ = "database_alerts"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    alert_type = Column(String(50), nullable=False)  # db_brute_force, db_new_admin, etc.
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    username = Column(String(100), nullable=True)
    source_ip = Column(String(45), nullable=True)
    affected_table = Column(String(100), nullable=True)
    evidence_json = Column(Text, nullable=True)  # Supporting data
    risk_score_impact = Column(Integer, default=0)  # How much this adds to risk score
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(Integer, nullable=True)  # FK to User
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class DatabaseAccessPattern(Base):
    """Baseline access patterns for anomaly detection."""
    __tablename__ = "database_access_patterns"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    username = Column(String(100), nullable=False)
    typical_hours_json = Column(Text, nullable=True)  # JSON: [9,10,11,...,17]
    typical_ips_json = Column(Text, nullable=True)  # JSON: ["192.168.1.100", ...]
    typical_connection_duration_minutes = Column(Integer, nullable=True)
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DatabaseActivityBaseline(Base):
    """Activity baselines for anomaly detection."""
    __tablename__ = "database_activity_baselines"

    id = Column(Integer, primary_key=True, index=True)
    database_id = Column(Integer, nullable=False, index=True)
    username = Column(String(100), nullable=False)
    avg_queries_per_hour = Column(Float, default=0.0)
    avg_rows_read = Column(Float, default=0.0)
    baseline_created = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ── Canonical normalized event model ─────────────────────────────────────

class SecurityEvent(Base):
    """
    Normalized security event (canonical model). Every collector's telemetry is
    converted to this shape before detection/correlation consume it.
    Source-specific data is kept in `attributes`; the raw record is referenced
    by `raw_event_reference` rather than copied.
    """
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), nullable=False, unique=True)            # UUID assigned at normalization
    event_type = Column(String(50), nullable=False, index=True)           # normalized category
    timestamp = Column(DateTime, nullable=False, index=True)              # when the event occurred (see attributes.timestamp_source)
    ingestion_timestamp = Column(DateTime, nullable=False)                # when Skylos received it
    source_type = Column(String(50), nullable=False, index=True)          # agent_log, attack_simulator, ...
    source_id = Column(String(100), nullable=True)                        # collector identity, when one exists
    asset_id = Column(Integer, nullable=True, index=True)                 # protected asset (e.g. database_assets.id)
    device_id = Column(String(100), nullable=True)                        # endpoint device identity
    actor = Column(String(255), nullable=True, index=True)
    actor_type = Column(String(30), nullable=True)                        # user, service, unknown
    source_address = Column(String(45), nullable=True, index=True)
    destination_address = Column(String(45), nullable=True)
    action = Column(String(50), nullable=False)
    object_type = Column(String(50), nullable=True)
    object_name = Column(String(255), nullable=True)
    outcome = Column(String(20), nullable=False, default="unknown")       # success, failure, unknown
    severity_hint = Column(String(20), nullable=True)                     # as reported by the source, if any
    raw_event_reference = Column(String(100), nullable=True, unique=True) # e.g. "logs:42" — at most one event per raw record
    attributes = Column(JSON, nullable=True)                              # source-specific structured data
    correlation_key = Column(String(255), nullable=True, index=True)

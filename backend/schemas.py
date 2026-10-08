"""
AI-SIEM Guardian — Pydantic Schemas
Request / response validation for all API endpoints.
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Any, Dict, Optional
from datetime import datetime
import re


# ── Auth Schemas ────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")

    @validator('username')
    def username_must_be_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only alphanumeric characters, underscores, and hyphens')
        return v


class UserLogin(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


# ── Log Schemas ─────────────────────────────────────────────

class LogCreate(BaseModel):
    user: Optional[str] = Field(None, max_length=50)
    ip: str = Field(..., pattern=r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    event_type: str = Field(..., max_length=50)
    failed_attempts: int = Field(default=0, ge=0)
    login_frequency: float = Field(default=0.0, ge=0.0)
    ip_activity_rate: float = Field(default=0.0, ge=0.0)
    raw_data: Optional[str] = Field(None, max_length=65535)  # 64KB limit


class LogOut(BaseModel):
    id: int
    user: Optional[str]
    ip: str
    event_type: str
    failed_attempts: int
    login_frequency: float
    ip_activity_rate: float
    anomaly: bool
    raw_data: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Alert Schemas ───────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    log_id: Optional[int]
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    message: str = Field(..., max_length=1000)
    ip: Optional[str] = Field(None, pattern=r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    alert_type: Optional[str] = Field(None, max_length=50)
    acknowledged: bool
    timestamp: datetime

    class Config:
        from_attributes = True


class AlertAcknowledge(BaseModel):
    acknowledged: bool = True


# ── Network Activity Schemas ────────────────────────────────

class NetworkActivityCreate(BaseModel):
    ip: str = Field(..., pattern=r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    packets: int = Field(default=0, ge=0)
    bytes_transferred: int = Field(default=0, ge=0)
    protocol: Optional[str] = Field(None, max_length=20)
    suspicious: bool = False


class NetworkActivityOut(BaseModel):
    id: int
    ip: str
    packets: int
    bytes_transferred: int
    protocol: Optional[str]
    suspicious: bool
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Dashboard Schemas ───────────────────────────────────────

class DashboardStats(BaseModel):
    total_logs: int
    active_alerts: int
    network_events: int
    anomalies_detected: int
    system_status: str = Field(default="operational", pattern="^(operational|degraded|maintenance|offline)$")


class TimelineEvent(BaseModel):
    id: int
    event_type: str = Field(..., max_length=100)
    message: str = Field(..., max_length=500)
    ip: Optional[str] = Field(None, pattern=r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    timestamp: datetime


class SecurityEventOut(BaseModel):
    id: int
    event_id: str
    event_type: str
    timestamp: datetime
    ingestion_timestamp: datetime
    source_type: str
    source_id: Optional[str]
    asset_id: Optional[int]
    device_id: Optional[str]
    actor: Optional[str]
    actor_type: Optional[str]
    source_address: Optional[str]
    destination_address: Optional[str]
    action: str
    object_type: Optional[str]
    object_name: Optional[str]
    outcome: str
    severity_hint: Optional[str]
    raw_event_reference: Optional[str]
    attributes: Optional[Dict[str, Any]]
    correlation_key: Optional[str]

    class Config:
        from_attributes = True


# ── Database Guardian Schemas ────────────────────────────────

class DatabaseAssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    db_type: str = Field(..., pattern="^(sqlite|postgresql)$")
    host: Optional[str] = Field(None, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    database_name: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=255)  # Will be encrypted

class DatabaseAssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None

class DatabaseAssetOut(BaseModel):
    id: int
    name: str
    db_type: str
    host: Optional[str]
    port: Optional[int]
    database_name: str
    username: str
    is_active: bool
    last_check: Optional[datetime]
    status: str
    risk_score: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class DatabaseHealthOut(BaseModel):
    id: int
    database_id: int
    check_time: datetime
    status: str
    response_time_ms: Optional[int]
    connection_count: Optional[int]
    database_size_mb: Optional[int]
    error_message: Optional[str]

    class Config:
        from_attributes = True

class DatabaseAlertOut(BaseModel):
    id: int
    database_id: int
    alert_type: str
    severity: str
    title: str
    description: str
    username: Optional[str]
    source_ip: Optional[str]
    affected_table: Optional[str]
    risk_score_impact: int
    acknowledged: bool
    timestamp: datetime

    class Config:
        from_attributes = True

class DatabaseActivityStats(BaseModel):
    total_databases: int
    online_databases: int
    offline_databases: int
    total_alerts: int
    high_risk_databases: int  # risk_score >= 50

class DatabaseRiskScoreBreakdown(BaseModel):
    database_id: int
    database_name: str
    total_risk_score: int
    failed_logins_score: int
    privilege_changes_score: int
    schema_changes_score: int
    audit_disabled_score: int
    backup_issues_score: int
    sensitive_access_score: int
    other_score: int

"""
Unit tests for database models.
"""
import os
# Set environment variables before importing the app modules
os.environ['DEBUG'] = 'true'
os.environ['JWT_SECRET_KEY'] = '0123456789abcdef0123456789abcdef'  # 32 chars
os.environ['AGENT_API_KEY'] = 'test-agent-key'
# Add other required environment variables if needed
os.environ['DATABASE_URL'] = 'sqlite:///./test.db'
os.environ['CORS_ORIGINS'] = '["http://localhost:3000"]'

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone
import enum

from models import (
    User, UserRole, Log, Alert, NetworkActivity, AuditLog,
    DatabaseAsset, DatabaseHealthCheck, DatabaseLoginEvent,
    DatabaseUser, DatabasePrivilegeChange, DatabaseQueryLog,
    DatabaseSchemaChange, DatabaseConfigChange, DatabaseBackup,
    DatabaseAlert, DatabaseAccessPattern, DatabaseActivityBaseline
)
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text, Enum as SAEnum


class TestUserModel:
    """Test User model."""

    def test_user_creation(self):
        """Test creating a User instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashedpass",
            role="admin",
            is_active=True,
            created_at=fixed_time
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.hashed_password == "hashedpass"
        assert user.role == "admin"
        assert user.is_active is True
        assert user.id is None  # Not set until saved to DB
        assert user.created_at == fixed_time

    def test_user_role_enum(self):
        """Test UserRole enum."""
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.ANALYST.value == "analyst"
        assert UserRole.VIEWER.value == "viewer"

        # Test that we can iterate
        roles = list(UserRole)
        assert len(roles) == 3
        assert UserRole.ADMIN in roles
        assert UserRole.ANALYST in roles
        assert UserRole.VIEWER in roles


class TestLogModel:
    """Test Log model."""

    def test_log_creation(self):
        """Test creating a Log instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        log = Log(
            user="testuser",
            ip="192.168.1.100",
            event_type="login",
            failed_attempts=3,
            login_frequency=5.5,
            ip_activity_rate=10.0,
            anomaly=True,
            raw_data='{"test": "data"}',
            timestamp=fixed_time
        )

        assert log.user == "testuser"
        assert log.ip == "192.168.1.100"
        assert log.event_type == "login"
        assert log.failed_attempts == 3
        assert log.login_frequency == 5.5
        assert log.ip_activity_rate == 10.0
        assert log.anomaly is True
        assert log.raw_data == '{"test": "data"}'
        assert log.id is None
        assert log.timestamp == fixed_time

    def test_log_column_defaults(self):
        """Test that Log model columns have expected default values."""
        # Check that columns have the expected defaults defined
        assert Log.failed_attempts.default.arg == 0
        assert Log.login_frequency.default.arg == 0.0
        assert Log.ip_activity_rate.default.arg == 0.0
        assert Log.anomaly.default.arg == False
        # raw_data is nullable=True with no default, so default is None
        assert Log.raw_data.default is None
        # timestamp has a lambda default, so we can't easily test the arg
        # but we can test that it exists
        assert Log.timestamp.default is not None


class TestAlertModel:
    """Test Alert model."""

    def test_alert_creation(self):
        """Test creating an Alert instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alert = Alert(
            log_id=1,
            severity="high",
            message="Brute force attack detected",
            ip="192.168.1.100",
            alert_type="brute_force",
            acknowledged=False,
            timestamp=fixed_time
        )

        assert alert.log_id == 1
        assert alert.severity == "high"
        assert alert.message == "Brute force attack detected"
        assert alert.ip == "192.168.1.100"
        assert alert.alert_type == "brute_force"
        assert alert.acknowledged is False
        assert alert.id is None
        assert alert.timestamp == fixed_time

    def test_alert_column_defaults(self):
        """Test that Alert model columns have expected default values."""
        # Check that columns have the expected defaults defined
        assert Alert.severity.default.arg == "medium"
        assert Alert.acknowledged.default.arg == False
        # log_id, ip, alert_type are nullable with no defaults
        assert Alert.log_id.default is None
        assert Alert.ip.default is None
        assert Alert.alert_type.default is None
        # timestamp has a lambda default
        assert Alert.timestamp.default is not None
        # message is nullable=False with no default (must be provided)


class TestNetworkActivityModel:
    """Test NetworkActivity model."""

    def test_network_activity_creation(self):
        """Test creating a NetworkActivity instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        activity = NetworkActivity(
            ip="192.168.1.100",
            packets=150,
            bytes_transferred=10240,
            protocol="TCP",
            suspicious=True,
            timestamp=fixed_time
        )

        assert activity.ip == "192.168.1.100"
        assert activity.packets == 150
        assert activity.bytes_transferred == 10240
        assert activity.protocol == "TCP"
        assert activity.suspicious is True
        assert activity.id is None
        assert activity.timestamp == fixed_time

    def test_network_activity_column_defaults(self):
        """Test that NetworkActivity model columns have expected default values."""
        # Check that columns have the expected defaults defined
        assert NetworkActivity.packets.default.arg == 0
        assert NetworkActivity.bytes_transferred.default.arg == 0
        assert NetworkActivity.suspicious.default.arg == False
        # ip is nullable=False with no default (must be provided)
        # protocol is nullable=True with no default
        # timestamp has a lambda default
        assert NetworkActivity.timestamp.default is not None


class TestAuditLogModel:
    """Test AuditLog model."""

    def test_audit_log_creation(self):
        """Test creating an AuditLog instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        audit = AuditLog(
            user_id=1,
            action="user_login",
            details="User testuser logged in successfully",
            timestamp=fixed_time
        )

        assert audit.user_id == 1
        assert audit.action == "user_login"
        assert audit.details == "User testuser logged in successfully"
        assert audit.id is None
        assert audit.timestamp == fixed_time

    def test_audit_log_column_defaults(self):
        """Test that AuditLog model columns have expected default values."""
        # Check that columns have the expected defaults defined
        # user_id is nullable=True with no default
        assert AuditLog.user_id.default is None
        # action is nullable=False with no default (must be provided)
        # details is nullable=True with no default
        # timestamp has a lambda default
        assert AuditLog.timestamp.default is not None


class TestDatabaseAssetModel:
    """Test DatabaseAsset model."""

    def test_database_asset_creation(self):
        """Test creating a DatabaseAsset instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        asset = DatabaseAsset(
            name="test_db",
            db_type="postgresql",
            host="localhost",
            port=5432,
            database_name="testdb",
            username="dbuser",
            encrypted_password="encryptedpass",
            is_active=True,
            status="online",
            risk_score=45,
            created_at=fixed_time,
            updated_at=fixed_time
        )

        assert asset.name == "test_db"
        assert asset.db_type == "postgresql"
        assert asset.host == "localhost"
        assert asset.port == 5432
        assert asset.database_name == "testdb"
        assert asset.username == "dbuser"
        assert asset.encrypted_password == "encryptedpass"
        assert asset.is_active is True
        assert asset.status == "online"
        assert asset.risk_score == 45
        assert asset.id is None
        assert asset.created_at == fixed_time
        assert asset.updated_at == fixed_time

    def test_database_asset_column_defaults(self):
        """Test that DatabaseAsset model columns have expected default values."""
        # Check that columns have the expected defaults defined
        assert DatabaseAsset.is_active.default.arg == True
        assert DatabaseAsset.status.default.arg == "unknown"
        assert DatabaseAsset.risk_score.default.arg == 0
        # name, db_type, database_name, username, encrypted_password are nullable=False with no defaults
        assert DatabaseAsset.name.default is None
        assert DatabaseAsset.db_type.default is None
        assert DatabaseAsset.database_name.default is None
        assert DatabaseAsset.username.default is None
        assert DatabaseAsset.encrypted_password.default is None
        # host, port are nullable=True with no defaults
        assert DatabaseAsset.host.default is None
        assert DatabaseAsset.port.default is None
        # last_check is nullable=True with no default
        assert DatabaseAsset.last_check.default is None
        # metadata_json is nullable=True with no default
        assert DatabaseAsset.metadata_json.default is None
        # created_at and updated_at have lambda defaults
        assert DatabaseAsset.created_at.default is not None
        assert DatabaseAsset.updated_at.default is not None


class TestDatabaseAlertModel:
    """Test DatabaseAlert model."""

    def test_database_alert_creation(self):
        """Test creating a DatabaseAlert instance."""
        fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alert = DatabaseAlert(
            database_id=1,
            alert_type="db_brute_force",
            severity="critical",
            title="Database Brute Force Attack",
            description="Multiple failed login attempts detected",
            username="dbuser",
            source_ip="192.168.1.100",
            affected_table="users",
            risk_score_impact=30,
            acknowledged=False,
            timestamp=fixed_time
        )

        assert alert.database_id == 1
        assert alert.alert_type == "db_brute_force"
        assert alert.severity == "critical"
        assert alert.title == "Database Brute Force Attack"
        assert alert.description == "Multiple failed login attempts detected"
        assert alert.username == "dbuser"
        assert alert.source_ip == "192.168.1.100"
        assert alert.affected_table == "users"
        assert alert.risk_score_impact == 30
        assert alert.acknowledged is False
        assert alert.id is None
        assert alert.timestamp == fixed_time

    def test_database_alert_column_defaults(self):
        """Test that DatabaseAlert model columns have expected default values."""
        # Check that columns have the expected defaults defined
        assert DatabaseAlert.severity.default.arg == "medium"
        assert DatabaseAlert.acknowledged.default.arg == False
        assert DatabaseAlert.risk_score_impact.default.arg == 0
        # database_id is nullable=False with no default (must be provided)
        # alert_type is nullable=False with no default (must be provided)
        # title, description are nullable=False with no defaults (must be provided)
        assert DatabaseAlert.title.default is None
        assert DatabaseAlert.description.default is None
        # username, source_ip, affected_table, evidence_json are nullable=True with no defaults
        assert DatabaseAlert.username.default is None
        assert DatabaseAlert.source_ip.default is None
        assert DatabaseAlert.affected_table.default is None
        assert DatabaseAlert.evidence_json.default is None
        # acknowledged_by is nullable=True with no default
        assert DatabaseAlert.acknowledged_by.default is None
        # timestamp has a lambda default
        assert DatabaseAlert.timestamp.default is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
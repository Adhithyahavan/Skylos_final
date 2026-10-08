"""baseline - schema as of 2026-10-01 (all tables previously created by create_all)

Revision ID: 0001
Revises:
Create Date: 2026-10-01

Earlier versions of Skylos built the schema with Base.metadata.create_all and
had no migrations. Existing databases therefore have some or all of these
tables already (for example, databases created before Database Guardian have
only the five core tables). This revision:

  * creates each baseline table only if it does not exist,
  * creates missing baseline indexes on tables that do exist,
  * verifies pre-existing tables contain every baseline column and aborts
    with an explanation if not (no data is modified or dropped).

Running it on an empty database creates the full schema; running it on a
legacy database adopts that database at this revision without data loss.

Table definitions are frozen here on purpose — do not import models.py.
"""
from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def _create_alerts():
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('log_id', sa.Integer(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('alert_type', sa.String(length=50), nullable=True),
        sa.Column('acknowledged', sa.Boolean(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_audit_logs():
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_access_patterns():
    op.create_table(
        'database_access_patterns',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('typical_hours_json', sa.Text(), nullable=True),
        sa.Column('typical_ips_json', sa.Text(), nullable=True),
        sa.Column('typical_connection_duration_minutes', sa.Integer(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_activity_baselines():
    op.create_table(
        'database_activity_baselines',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('avg_queries_per_hour', sa.Float(), nullable=True),
        sa.Column('avg_rows_read', sa.Float(), nullable=True),
        sa.Column('baseline_created', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_alerts():
    op.create_table(
        'database_alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('affected_table', sa.String(length=100), nullable=True),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.Column('risk_score_impact', sa.Integer(), nullable=True),
        sa.Column('acknowledged', sa.Boolean(), nullable=True),
        sa.Column('acknowledged_by', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_assets():
    op.create_table(
        'database_assets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('db_type', sa.String(length=20), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('database_name', sa.String(length=100), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('encrypted_password', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('last_check', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )


def _create_database_backups():
    op.create_table(
        'database_backups',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('backup_time', sa.DateTime(), nullable=False),
        sa.Column('backup_type', sa.String(length=20), nullable=False),
        sa.Column('backup_size_mb', sa.Integer(), nullable=True),
        sa.Column('backup_location', sa.String(length=255), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('verification_status', sa.String(length=20), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_config_changes():
    op.create_table(
        'database_config_changes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('parameter_name', sa.String(length=100), nullable=False),
        sa.Column('old_value', sa.Text(), nullable=True),
        sa.Column('new_value', sa.Text(), nullable=True),
        sa.Column('changed_by', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_health_checks():
    op.create_table(
        'database_health_checks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('check_time', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('connection_count', sa.Integer(), nullable=True),
        sa.Column('database_size_mb', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_login_events():
    op.create_table(
        'database_login_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('auth_method', sa.String(length=50), nullable=True),
        sa.Column('connection_duration', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_privilege_changes():
    op.create_table(
        'database_privilege_changes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('target_user', sa.String(length=100), nullable=False),
        sa.Column('change_type', sa.String(length=50), nullable=False),
        sa.Column('privilege', sa.String(length=100), nullable=True),
        sa.Column('granted_by', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_query_logs():
    op.create_table(
        'database_query_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('query_type', sa.String(length=20), nullable=False),
        sa.Column('table_name', sa.String(length=100), nullable=True),
        sa.Column('rows_affected', sa.Integer(), nullable=True),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('is_sensitive', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_schema_changes():
    op.create_table(
        'database_schema_changes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('change_type', sa.String(length=50), nullable=False),
        sa.Column('object_type', sa.String(length=50), nullable=False),
        sa.Column('object_name', sa.String(length=100), nullable=False),
        sa.Column('performed_by', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('details_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_database_users():
    op.create_table(
        'database_users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('is_admin', sa.Boolean(), nullable=True),
        sa.Column('privileges_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_logs():
    op.create_table(
        'logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user', sa.String(length=50), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('failed_attempts', sa.Integer(), nullable=True),
        sa.Column('login_frequency', sa.Float(), nullable=True),
        sa.Column('ip_activity_rate', sa.Float(), nullable=True),
        sa.Column('anomaly', sa.Boolean(), nullable=True),
        sa.Column('raw_data', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_network_activity():
    op.create_table(
        'network_activity',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('packets', sa.Integer(), nullable=True),
        sa.Column('bytes_transferred', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=20), nullable=True),
        sa.Column('suspicious', sa.Boolean(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def _create_users():
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )


TABLES = {
    'alerts': _create_alerts,
    'audit_logs': _create_audit_logs,
    'database_access_patterns': _create_database_access_patterns,
    'database_activity_baselines': _create_database_activity_baselines,
    'database_alerts': _create_database_alerts,
    'database_assets': _create_database_assets,
    'database_backups': _create_database_backups,
    'database_config_changes': _create_database_config_changes,
    'database_health_checks': _create_database_health_checks,
    'database_login_events': _create_database_login_events,
    'database_privilege_changes': _create_database_privilege_changes,
    'database_query_logs': _create_database_query_logs,
    'database_schema_changes': _create_database_schema_changes,
    'database_users': _create_database_users,
    'logs': _create_logs,
    'network_activity': _create_network_activity,
    'users': _create_users,
}

# Columns every baseline table must have (frozen copy of the definitions above)
BASELINE_COLUMNS = {
    'alerts': ['id', 'log_id', 'severity', 'message', 'ip', 'alert_type', 'acknowledged', 'timestamp'],
    'audit_logs': ['id', 'user_id', 'action', 'details', 'timestamp'],
    'database_access_patterns': ['id', 'database_id', 'username', 'typical_hours_json', 'typical_ips_json', 'typical_connection_duration_minutes', 'last_updated'],
    'database_activity_baselines': ['id', 'database_id', 'username', 'avg_queries_per_hour', 'avg_rows_read', 'baseline_created'],
    'database_alerts': ['id', 'database_id', 'alert_type', 'severity', 'title', 'description', 'username', 'source_ip', 'affected_table', 'evidence_json', 'risk_score_impact', 'acknowledged', 'acknowledged_by', 'timestamp'],
    'database_assets': ['id', 'name', 'db_type', 'host', 'port', 'database_name', 'username', 'encrypted_password', 'is_active', 'last_check', 'status', 'risk_score', 'metadata_json', 'created_at', 'updated_at'],
    'database_backups': ['id', 'database_id', 'backup_time', 'backup_type', 'backup_size_mb', 'backup_location', 'success', 'verification_status', 'error_message'],
    'database_config_changes': ['id', 'database_id', 'parameter_name', 'old_value', 'new_value', 'changed_by', 'timestamp'],
    'database_health_checks': ['id', 'database_id', 'check_time', 'status', 'response_time_ms', 'connection_count', 'database_size_mb', 'error_message'],
    'database_login_events': ['id', 'database_id', 'username', 'source_ip', 'success', 'timestamp', 'auth_method', 'connection_duration'],
    'database_privilege_changes': ['id', 'database_id', 'target_user', 'change_type', 'privilege', 'granted_by', 'timestamp'],
    'database_query_logs': ['id', 'database_id', 'username', 'source_ip', 'query_type', 'table_name', 'rows_affected', 'execution_time_ms', 'timestamp', 'is_sensitive'],
    'database_schema_changes': ['id', 'database_id', 'change_type', 'object_type', 'object_name', 'performed_by', 'timestamp', 'details_json'],
    'database_users': ['id', 'database_id', 'username', 'is_admin', 'privileges_json', 'created_at', 'last_seen'],
    'logs': ['id', 'user', 'ip', 'event_type', 'failed_attempts', 'login_frequency', 'ip_activity_rate', 'anomaly', 'raw_data', 'timestamp'],
    'network_activity': ['id', 'ip', 'packets', 'bytes_transferred', 'protocol', 'suspicious', 'timestamp'],
    'users': ['id', 'username', 'email', 'hashed_password', 'role', 'is_active', 'created_at'],
}

# (index name, table, columns, unique)
BASELINE_INDEXES = [
    ('ix_alerts_id', 'alerts', ['id'], False),
    ('ix_alerts_timestamp', 'alerts', ['timestamp'], False),
    ('ix_audit_logs_id', 'audit_logs', ['id'], False),
    ('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'], False),
    ('ix_database_access_patterns_database_id', 'database_access_patterns', ['database_id'], False),
    ('ix_database_access_patterns_id', 'database_access_patterns', ['id'], False),
    ('ix_database_activity_baselines_database_id', 'database_activity_baselines', ['database_id'], False),
    ('ix_database_activity_baselines_id', 'database_activity_baselines', ['id'], False),
    ('ix_database_alerts_database_id', 'database_alerts', ['database_id'], False),
    ('ix_database_alerts_id', 'database_alerts', ['id'], False),
    ('ix_database_alerts_timestamp', 'database_alerts', ['timestamp'], False),
    ('ix_database_assets_id', 'database_assets', ['id'], False),
    ('ix_database_backups_backup_time', 'database_backups', ['backup_time'], False),
    ('ix_database_backups_database_id', 'database_backups', ['database_id'], False),
    ('ix_database_backups_id', 'database_backups', ['id'], False),
    ('ix_database_config_changes_database_id', 'database_config_changes', ['database_id'], False),
    ('ix_database_config_changes_id', 'database_config_changes', ['id'], False),
    ('ix_database_config_changes_timestamp', 'database_config_changes', ['timestamp'], False),
    ('ix_database_health_checks_check_time', 'database_health_checks', ['check_time'], False),
    ('ix_database_health_checks_database_id', 'database_health_checks', ['database_id'], False),
    ('ix_database_health_checks_id', 'database_health_checks', ['id'], False),
    ('ix_database_login_events_database_id', 'database_login_events', ['database_id'], False),
    ('ix_database_login_events_id', 'database_login_events', ['id'], False),
    ('ix_database_login_events_source_ip', 'database_login_events', ['source_ip'], False),
    ('ix_database_login_events_timestamp', 'database_login_events', ['timestamp'], False),
    ('ix_database_login_events_username', 'database_login_events', ['username'], False),
    ('ix_database_privilege_changes_database_id', 'database_privilege_changes', ['database_id'], False),
    ('ix_database_privilege_changes_id', 'database_privilege_changes', ['id'], False),
    ('ix_database_privilege_changes_timestamp', 'database_privilege_changes', ['timestamp'], False),
    ('ix_database_query_logs_database_id', 'database_query_logs', ['database_id'], False),
    ('ix_database_query_logs_id', 'database_query_logs', ['id'], False),
    ('ix_database_query_logs_timestamp', 'database_query_logs', ['timestamp'], False),
    ('ix_database_schema_changes_database_id', 'database_schema_changes', ['database_id'], False),
    ('ix_database_schema_changes_id', 'database_schema_changes', ['id'], False),
    ('ix_database_schema_changes_timestamp', 'database_schema_changes', ['timestamp'], False),
    ('ix_database_users_database_id', 'database_users', ['database_id'], False),
    ('ix_database_users_id', 'database_users', ['id'], False),
    ('ix_logs_id', 'logs', ['id'], False),
    ('ix_logs_timestamp', 'logs', ['timestamp'], False),
    ('ix_network_activity_id', 'network_activity', ['id'], False),
    ('ix_network_activity_timestamp', 'network_activity', ['timestamp'], False),
    ('ix_users_id', 'users', ['id'], False),
    ('ix_users_username', 'users', ['username'], True),
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    problems = []
    for table, columns in BASELINE_COLUMNS.items():
        if table in existing:
            present = {c["name"] for c in inspector.get_columns(table)}
            missing = [c for c in columns if c not in present]
            if missing:
                problems.append(f"{table}: missing columns {missing}")
    if problems:
        raise RuntimeError(
            "Existing database schema does not match the Skylos baseline and cannot be "
            "adopted automatically. No changes were made. Back up the database and "
            "reconcile these differences manually: " + "; ".join(problems)
        )

    for table, create in TABLES.items():
        if table not in existing:
            create()

    inspector = sa.inspect(bind)  # refresh after creating tables
    for index_name, table, columns, unique in BASELINE_INDEXES:
        present = {ix["name"] for ix in inspector.get_indexes(table)}
        if index_name not in present:
            op.create_index(index_name, table, columns, unique=unique)


def downgrade() -> None:
    # Refuse: on adopted legacy databases these tables (and their data) predate
    # this revision, so dropping them would destroy data this migration never created.
    raise RuntimeError(
        "Downgrading below the baseline revision is not supported. "
        "Restore from a backup instead."
    )

"""
Migration tests (Alembic). Each test uses its own temporary SQLite file and
synthetic rows only.

Scenarios:
  * empty database      -> full schema at head, identical to models.py
  * legacy database     -> pre-migration schema built by create_all (DDL below is
                           the exact schema of a real pre-Database-Guardian
                           install) is adopted with data preserved
  * idempotency, incompatible legacy schema, downgrade refusal
"""
import pytest
from sqlalchemy import create_engine, inspect, text
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from database import Base, run_migrations, current_revision, _alembic_config, _run_alembic
import models  # noqa: F401

# Schema of a real legacy install (before Database Guardian), captured from
# sqlite_master. Schema only — no data was copied.
LEGACY_CORE_DDL = [
    """CREATE TABLE alerts (id INTEGER NOT NULL, log_id INTEGER, severity VARCHAR(20), message TEXT NOT NULL,
       ip VARCHAR(45), alert_type VARCHAR(50), acknowledged BOOLEAN, timestamp DATETIME, PRIMARY KEY (id))""",
    """CREATE TABLE audit_logs (id INTEGER NOT NULL, user_id INTEGER, action VARCHAR(100) NOT NULL, details TEXT,
       timestamp DATETIME, PRIMARY KEY (id))""",
    """CREATE TABLE logs (id INTEGER NOT NULL, user VARCHAR(50), ip VARCHAR(45) NOT NULL, event_type VARCHAR(50) NOT NULL,
       failed_attempts INTEGER, login_frequency FLOAT, ip_activity_rate FLOAT, anomaly BOOLEAN, raw_data TEXT,
       timestamp DATETIME, PRIMARY KEY (id))""",
    """CREATE TABLE network_activity (id INTEGER NOT NULL, ip VARCHAR(45) NOT NULL, packets INTEGER,
       bytes_transferred INTEGER, protocol VARCHAR(20), suspicious BOOLEAN, timestamp DATETIME, PRIMARY KEY (id))""",
    """CREATE TABLE users (id INTEGER NOT NULL, username VARCHAR(50) NOT NULL, email VARCHAR(120) NOT NULL,
       hashed_password VARCHAR(255) NOT NULL, role VARCHAR(20) NOT NULL, is_active BOOLEAN, created_at DATETIME,
       PRIMARY KEY (id), UNIQUE (email))""",
    "CREATE INDEX ix_alerts_id ON alerts (id)",
    "CREATE INDEX ix_alerts_timestamp ON alerts (timestamp)",
    "CREATE INDEX ix_audit_logs_id ON audit_logs (id)",
    "CREATE INDEX ix_audit_logs_timestamp ON audit_logs (timestamp)",
    "CREATE INDEX ix_logs_id ON logs (id)",
    "CREATE INDEX ix_logs_timestamp ON logs (timestamp)",
    "CREATE INDEX ix_network_activity_id ON network_activity (id)",
    "CREATE INDEX ix_network_activity_timestamp ON network_activity (timestamp)",
    "CREATE INDEX ix_users_id ON users (id)",
    "CREATE UNIQUE INDEX ix_users_username ON users (username)",
]


@pytest.fixture
def make_engine(tmp_path):
    engines = []

    def _make(name="m.db"):
        eng = create_engine(f"sqlite:///{(tmp_path / name).as_posix()}")
        engines.append(eng)
        return eng
    yield _make
    for eng in engines:
        eng.dispose()


def _head():
    return ScriptDirectory.from_config(_alembic_config()).get_current_head()


def _baseline_tables():
    """Tables of the frozen 0001 baseline (pre-migration installs never had later tables)."""
    module = ScriptDirectory.from_config(_alembic_config()).get_revision("0001").module
    return set(module.BASELINE_COLUMNS)


def _schema_diff(engine):
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(ctx, Base.metadata)


def _tables(engine):
    return set(inspect(engine).get_table_names()) - {"alembic_version"}


def test_single_linear_head():
    heads = ScriptDirectory.from_config(_alembic_config()).get_heads()
    assert len(heads) == 1, f"multiple migration heads: {heads}"


def test_empty_database_upgrades_to_head_matching_models(make_engine):
    eng = make_engine()
    assert current_revision(eng) is None
    run_migrations(eng)
    assert current_revision(eng) == _head()
    assert _tables(eng) == set(Base.metadata.tables)
    # Guard: models.py and the migrations must describe the same schema.
    # If this fails after editing models.py, write a migration
    # (alembic revision --autogenerate -m "...") and review it.
    assert _schema_diff(eng) == []


def test_legacy_core_database_is_adopted_without_data_loss(make_engine):
    eng = make_engine()
    with eng.begin() as conn:
        for ddl in LEGACY_CORE_DDL:
            conn.execute(text(ddl))
        conn.execute(text("INSERT INTO users (id, username, email, hashed_password, role, is_active) "
                          "VALUES (1, 'legacy_user', 'legacy@example.com', 'x-hash', 'analyst', 1)"))
        conn.execute(text("INSERT INTO logs (id, user, ip, event_type, failed_attempts, anomaly) "
                          "VALUES (1, 'legacy_user', '192.168.1.5', 'login', 3, 0)"))
        conn.execute(text("INSERT INTO alerts (id, severity, message, ip, acknowledged) "
                          "VALUES (1, 'high', 'synthetic legacy alert', '10.0.0.5', 0)"))

    run_migrations(eng)

    assert current_revision(eng) == _head()
    assert _tables(eng) == set(Base.metadata.tables)  # Database Guardian tables added
    with eng.connect() as conn:
        assert conn.execute(text("SELECT username, role FROM users")).all() == [("legacy_user", "analyst")]
        assert conn.execute(text("SELECT count(*) FROM logs")).scalar() == 1
        assert conn.execute(text("SELECT message FROM alerts")).scalar() == "synthetic legacy alert"
    assert _schema_diff(eng) == []


def test_legacy_full_create_all_database_is_adopted(make_engine):
    eng = make_engine()
    # What every startup did before migrations existed: create_all of the models
    # as they were then (= the baseline table set, not today's models).
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in _baseline_tables()])
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO database_assets (name, db_type, database_name, username, encrypted_password) "
                          "VALUES ('synthetic-db', 'sqlite', 'synthetic.db', 'u', 'enc')"))
    run_migrations(eng)
    assert current_revision(eng) == _head()
    with eng.connect() as conn:
        assert conn.execute(text("SELECT name FROM database_assets")).scalar() == "synthetic-db"
    assert _schema_diff(eng) == []


def test_upgrade_is_idempotent(make_engine):
    eng = make_engine()
    run_migrations(eng)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO audit_logs (action, details) VALUES ('synthetic', 'kept')"))
    run_migrations(eng)
    run_migrations(eng)
    assert current_revision(eng) == _head()
    with eng.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_logs")).scalar() == 1


def test_incompatible_legacy_schema_is_refused_without_changes(make_engine):
    eng = make_engine()
    with eng.begin() as conn:
        # users table lacking hashed_password: cannot be adopted safely
        conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(50), email VARCHAR(120), "
                          "role VARCHAR(20), is_active BOOLEAN, created_at DATETIME)"))
        conn.execute(text("INSERT INTO users (id, username, email, role) VALUES (1, 'u', 'u@example.com', 'viewer')"))

    with pytest.raises(RuntimeError, match="hashed_password"):
        run_migrations(eng)

    assert current_revision(eng) is None
    assert _tables(eng) == {"users"}  # nothing else created
    with eng.connect() as conn:
        assert conn.execute(text("SELECT username FROM users")).scalar() == "u"


def test_downgrade_below_baseline_refused_and_leaves_schema_untouched(make_engine):
    # Downgrading to base runs 0002's downgrade before 0001 refuses. The whole
    # operation must roll back (regression: on SQLite the DROP TABLE used to
    # persist while the version row said 0002).
    from alembic import command
    eng = make_engine()
    run_migrations(eng)
    with pytest.raises(RuntimeError, match="not supported"):
        _run_alembic(eng, lambda cfg: command.downgrade(cfg, "base"))
    assert current_revision(eng) == _head()
    assert _tables(eng) == set(Base.metadata.tables)
    assert _schema_diff(eng) == []


def test_failed_upgrade_rolls_back_every_step(make_engine):
    # Empty DB except a conflicting security_events table: 0001 would succeed,
    # 0002 fails. Nothing from 0001 may remain.
    eng = make_engine()
    with eng.begin() as conn:
        conn.execute(text("CREATE TABLE security_events (id INTEGER PRIMARY KEY, note TEXT)"))
        conn.execute(text("INSERT INTO security_events (note) VALUES ('pre-existing')"))
    with pytest.raises(Exception):
        run_migrations(eng)
    assert current_revision(eng) is None
    assert _tables(eng) == {"security_events"}
    with eng.connect() as conn:
        assert conn.execute(text("SELECT note FROM security_events")).scalar() == "pre-existing"


# ── Migration 0002: security_events ──────────────────────────────

CANONICAL_EVENT_FIELDS = {
    "event_id", "event_type", "timestamp", "ingestion_timestamp", "source_type", "source_id",
    "asset_id", "device_id", "actor", "actor_type", "source_address", "destination_address",
    "action", "object_type", "object_name", "outcome", "severity_hint", "raw_event_reference",
    "attributes", "correlation_key",
}


def test_0002_creates_security_events_with_canonical_fields(make_engine):
    eng = make_engine()
    run_migrations(eng, revision="0001")
    assert "security_events" not in _tables(eng)
    run_migrations(eng, revision="0002")
    assert current_revision(eng) == "0002"
    cols = {c["name"] for c in inspect(eng).get_columns("security_events")}
    assert cols == CANONICAL_EVENT_FIELDS | {"id"}
    uniques = {tuple(u["column_names"]) for u in inspect(eng).get_unique_constraints("security_events")}
    assert ("event_id",) in uniques and ("raw_event_reference",) in uniques


def test_0002_upgrade_preserves_existing_data(make_engine):
    eng = make_engine()
    run_migrations(eng, revision="0001")
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO logs (id, ip, event_type) VALUES (7, '10.0.0.5', 'login')"))
    run_migrations(eng)
    assert current_revision(eng) == _head()
    with eng.connect() as conn:
        assert conn.execute(text("SELECT ip FROM logs WHERE id = 7")).scalar() == "10.0.0.5"
        assert conn.execute(text("SELECT count(*) FROM security_events")).scalar() == 0
    assert _schema_diff(eng) == []


def test_0002_downgrade_removes_only_security_events(make_engine):
    from alembic import command
    eng = make_engine()
    run_migrations(eng)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO logs (id, ip, event_type) VALUES (1, '10.0.0.5', 'login')"))
    _run_alembic(eng, lambda cfg: command.downgrade(cfg, "0001"))
    assert current_revision(eng) == "0001"
    assert _tables(eng) == _baseline_tables()
    with eng.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM logs")).scalar() == 1
    run_migrations(eng)
    assert current_revision(eng) == _head() and _schema_diff(eng) == []


# ── Migration 0003: database_risk_snapshots ──────────────────────

def test_0003_creates_risk_snapshots_and_preserves_data(make_engine):
    eng = make_engine()
    run_migrations(eng, revision="0002")
    assert "database_risk_snapshots" not in _tables(eng)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO logs (id, ip, event_type) VALUES (3, '10.0.0.5', 'login')"))
    run_migrations(eng)
    assert current_revision(eng) == _head()
    cols = {c["name"] for c in inspect(eng).get_columns("database_risk_snapshots")}
    assert cols == {"id", "database_id", "calculated_at", "total_score", "severity",
                    "contributions_json", "scoring_version"}
    with eng.connect() as conn:
        assert conn.execute(text("SELECT ip FROM logs WHERE id = 3")).scalar() == "10.0.0.5"
    assert _schema_diff(eng) == []


def test_0003_downgrade_removes_only_risk_snapshots(make_engine):
    from alembic import command
    eng = make_engine()
    run_migrations(eng)
    _run_alembic(eng, lambda cfg: command.downgrade(cfg, "0002"))
    assert current_revision(eng) == "0002"
    assert "database_risk_snapshots" not in _tables(eng) and "security_events" in _tables(eng)
    run_migrations(eng)
    assert current_revision(eng) == _head() and _schema_diff(eng) == []

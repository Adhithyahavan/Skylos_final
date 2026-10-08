"""
AI-SIEM Guardian — Database Module
SQLAlchemy engine + session factory. Supports SQLite (default) and PostgreSQL.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import settings

# ── Engine Setup ─────────────────────────────────────────────────
# SQLite requires `check_same_thread=False` for FastAPI's async workers
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.SQL_ECHO,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _alembic_config():
    from pathlib import Path
    from alembic.config import Config

    backend_dir = Path(__file__).resolve().parent
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "migrations"))
    return cfg


def run_migrations(bind=None, revision: str = "head"):
    """
    Upgrade the database schema to `revision` with Alembic.
    Handles empty databases (full schema is created) and legacy databases built
    by create_all before migrations existed (adopted at the baseline revision).
    """
    import logging
    from alembic import command

    target = bind if bind is not None else engine
    _run_alembic(target, lambda cfg: command.upgrade(cfg, revision))
    logging.getLogger(__name__).info("Database schema is at revision %s", current_revision(target))


def _run_alembic(target, operation):
    """
    Run an Alembic command inside ONE transaction, so a failing step leaves the
    schema exactly as it was.

    pysqlite executes DDL outside transactions, so on SQLite a failed
    multi-step migration would leave earlier steps applied while the version
    row rolls back. For SQLite we therefore use a dedicated, migration-only
    engine that emits an explicit BEGIN (SQLAlchemy's documented recipe). The
    application's engine is not changed. PostgreSQL DDL is transactional already.
    """
    migration_engine, owned = target, False
    if target.dialect.name == "sqlite":
        from sqlalchemy import event
        from sqlalchemy.pool import NullPool

        migration_engine, owned = create_engine(target.url, poolclass=NullPool), True

        @event.listens_for(migration_engine, "connect")
        def _disable_pysqlite_transaction_handling(dbapi_connection, _record):
            dbapi_connection.isolation_level = None

        @event.listens_for(migration_engine, "begin")
        def _emit_begin(connection):
            connection.exec_driver_sql("BEGIN")

    try:
        cfg = _alembic_config()
        with migration_engine.begin() as connection:
            cfg.attributes["connection"] = connection
            operation(cfg)
    finally:
        if owned:
            migration_engine.dispose()


def current_revision(bind=None):
    """Return the Alembic revision recorded in the database, or None."""
    from alembic.runtime.migration import MigrationContext

    target = bind if bind is not None else engine
    with target.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def init_db():
    """Bring the schema up to date. Replaces the former Base.metadata.create_all."""
    run_migrations()

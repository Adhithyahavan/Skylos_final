"""
Skylos — Alembic environment.

Programmatic use (database.run_migrations) passes an open connection through
`config.attributes["connection"]`. CLI use connects with settings.DATABASE_URL.
The URL is never written into alembic.ini.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from config import settings
from database import Base
import models  # noqa: F401  — registers every table on Base.metadata

config = context.config
target_metadata = Base.metadata

# Only configure logging for the alembic CLI. Called from the app, fileConfig
# would reset the application's logging configuration.
if config.config_file_name is not None and "connection" not in config.attributes:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _configure(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot ALTER most things in place; batch mode rebuilds tables
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline():
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=settings.DATABASE_URL.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    engine = create_engine(settings.DATABASE_URL, poolclass=pool.NullPool)
    with engine.connect() as conn:
        _configure(conn)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

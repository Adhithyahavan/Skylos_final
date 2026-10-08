"""
Shared pytest configuration for Skylos backend tests.

Configuration is pinned here, before any test module imports `config`, so the
settings singleton is built from these values and tests never touch a real
database. All data used by tests is synthetic.
"""
import os
import sys
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="skylos-tests-")

from cryptography.fernet import Fernet  # noqa: E402

# Test-only encryption key, generated per test session and never printed.
TEST_DB_ENCRYPTION_KEY = Fernet.generate_key().decode()

os.environ.update({
    "DEBUG": "false",
    "JWT_SECRET_KEY": "test-only-jwt-secret-0123456789abcdef0123456789",
    "AGENT_API_KEY": "test-agent-key-0123456789abcdef",
    "DATABASE_URL": "sqlite:///" + os.path.join(_TMP_DIR, "skylos_test.db").replace("\\", "/"),
    "CORS_ORIGINS": "http://localhost:5173",
    "RATE_LIMIT_PER_MINUTE": "1000",
    "LOGIN_RATE_LIMIT_PER_MINUTE": "5",
    "MIN_TRAINING_SAMPLES": "10",
    "ANOMALY_CONTAMINATION": "0.1",
    "DB_GUARDIAN_MONITORING_ENABLED": "false",
    "SECRET_PROVIDER": "fernet",
    "DB_ENCRYPTION_KEY": TEST_DB_ENCRYPTION_KEY,
})
for _var in ("SKYLOS_BOOTSTRAP_ADMIN_USERNAME", "SKYLOS_BOOTSTRAP_ADMIN_EMAIL",
             "SKYLOS_BOOTSTRAP_ADMIN_PASSWORD", "SKYLOS_ADMIN_PASSWORD"):
    os.environ.pop(_var, None)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import config  # noqa: E402,F401  — freeze settings with the values above

import pytest  # noqa: E402

ADMIN_PASSWORD = "Adm1nPassw0rd!"
ANALYST_PASSWORD = "Analyst1Passw0rd"
VIEWER_PASSWORD = "Viewer1Passw0rd"


@pytest.fixture
def db_session():
    """Fresh schema for every test, built by the Alembic migrations (not create_all)."""
    from sqlalchemy import text
    from database import Base, engine, SessionLocal, run_migrations
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    run_migrations(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    """TestClient against the real FastAPI app (lifespan included)."""
    from fastapi.testclient import TestClient
    import api_routes
    import main
    from secret_provider import reset_secret_provider
    api_routes.limiter.reset()
    reset_secret_provider()
    with TestClient(main.app) as c:
        yield c


def _make_user(db, username, role, password):
    from auth import hash_password
    from models import User
    user = User(username=username, email=f"{username}@example.com",
                hashed_password=hash_password(password), role=role, is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def users(db_session):
    return {
        "admin": _make_user(db_session, "admin_t", "admin", ADMIN_PASSWORD),
        "analyst": _make_user(db_session, "analyst_t", "analyst", ANALYST_PASSWORD),
        "viewer": _make_user(db_session, "viewer_t", "viewer", VIEWER_PASSWORD),
    }


@pytest.fixture
def auth_headers(client, users):
    """Bearer headers per role, obtained through the real login endpoint."""
    creds = {"admin": ("admin_t", ADMIN_PASSWORD),
             "analyst": ("analyst_t", ANALYST_PASSWORD),
             "viewer": ("viewer_t", VIEWER_PASSWORD)}
    headers = {}
    for role, (u, p) in creds.items():
        r = client.post("/api/auth/login", json={"username": u, "password": p})
        assert r.status_code == 200, r.text
        headers[role] = {"Authorization": f"Bearer {r.json()['access_token']}"}
    import api_routes
    api_routes.limiter.reset()  # logins above must not consume the per-test login budget
    return headers


@pytest.fixture
def agent_headers():
    # Read from settings: legacy test modules overwrite os.environ after settings are frozen
    from config import settings
    return {"X-API-Key": settings.AGENT_API_KEY}

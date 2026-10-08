"""
API tests against the real Skylos FastAPI app (TestClient, temp SQLite, synthetic data).

Covers the original endpoint scenarios plus server-side authorization, agent
authentication, input validation, SQL-injection resistance, rate limiting,
WebSocket authentication and first-run administrator bootstrap.
"""
from unittest.mock import patch

import pytest
from starlette.websockets import WebSocketDisconnect

from conftest import ADMIN_PASSWORD, VIEWER_PASSWORD


def _audit_actions(db_session):
    from models import AuditLog
    db_session.expire_all()
    return [a.action for a in db_session.query(AuditLog).all()]


# ═══════════════════════════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════════════════════════

def test_app_starts_and_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_database_guardian_monitoring_module_imports():
    # Regression: bare imports in monitoring_service crashed app startup.
    import database_guardian.monitoring_service as ms
    assert callable(ms.start_monitoring)


def test_no_default_admin_is_created(client, db_session):
    from models import User
    assert db_session.query(User).count() == 0


# ═══════════════════════════════════════════════════════════════
# Unauthenticated access
# ═══════════════════════════════════════════════════════════════

PROTECTED_GETS = [
    "/api/auth/me",
    "/api/logs/",
    "/api/logs/count",
    "/api/alerts/",
    "/api/alerts/count",
    "/api/network/activity",
    "/api/network/top-ips",
    "/api/network/stats",
    "/api/dashboard/stats",
    "/api/dashboard/timeline",
    "/api/dashboard/login-timeline",
    "/api/dashboard/alert-frequency",
    "/api/dashboard/top-suspicious-ips",
]


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_read_endpoints_require_authentication(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_read_endpoints_allow_viewer(client, auth_headers, path):
    assert client.get(path, headers=auth_headers["viewer"]).status_code == 200


@pytest.mark.parametrize("path", ["/api/logs/", "/api/auth/me"])
def test_invalid_and_malformed_tokens_rejected(client, path):
    for value in ["Bearer abc", "Bearer a.b.c", "Bearer ", "Basic Zm9vOmJhcg=="]:
        r = client.get(path, headers={"Authorization": value})
        assert r.status_code == 401, value


def test_token_for_deleted_user_rejected(client, auth_headers, db_session, users):
    db_session.delete(users["viewer"])
    db_session.commit()
    assert client.get("/api/auth/me", headers=auth_headers["viewer"]).status_code == 401


def test_disabled_user_token_rejected(client, auth_headers, db_session, users):
    users["viewer"].is_active = False
    db_session.commit()
    assert client.get("/api/auth/me", headers=auth_headers["viewer"]).status_code == 403


# ═══════════════════════════════════════════════════════════════
# User creation (formerly open self-registration)
# ═══════════════════════════════════════════════════════════════

NEW_USER = {"username": "newuser", "email": "newuser@example.com", "password": "NewUserPass1", "role": "viewer"}


def test_anonymous_cannot_register_admin(client):
    r = client.post("/api/auth/register", json={**NEW_USER, "role": "admin"})
    assert r.status_code == 401


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_non_admin_cannot_create_users(client, auth_headers, role):
    r = client.post("/api/auth/register", json={**NEW_USER, "role": "admin"}, headers=auth_headers[role])
    assert r.status_code == 403


def test_admin_creates_user_and_is_audited(client, auth_headers, db_session):
    r = client.post("/api/auth/register", json=NEW_USER, headers=auth_headers["admin"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["username"] == "newuser" and body["role"] == "viewer"
    assert "hashed_password" not in body and "password" not in body
    assert "user_created" in _audit_actions(db_session)


def test_register_weak_password(client, auth_headers):
    r = client.post("/api/auth/register", json={**NEW_USER, "password": "weakpassword"}, headers=auth_headers["admin"])
    assert r.status_code == 400


def test_register_duplicate_username(client, auth_headers):
    r = client.post("/api/auth/register", json={**NEW_USER, "username": "viewer_t"}, headers=auth_headers["admin"])
    assert r.status_code == 400
    assert r.json()["detail"] == "Username already exists"


def test_register_duplicate_email(client, auth_headers):
    r = client.post("/api/auth/register", json={**NEW_USER, "email": "viewer_t@example.com"}, headers=auth_headers["admin"])
    assert r.status_code == 400
    assert r.json()["detail"] == "Email already registered"


def test_register_rejects_unknown_role(client, auth_headers):
    r = client.post("/api/auth/register", json={**NEW_USER, "role": "superuser"}, headers=auth_headers["admin"])
    assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════
# Login
# ═══════════════════════════════════════════════════════════════

def test_login_success_and_me(client, users, db_session):
    r = client.post("/api/auth/login", json={"username": "admin_t", "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "admin" and body["token_type"] == "bearer"
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200 and me.json()["username"] == "admin_t"
    assert "login" in _audit_actions(db_session)


def test_login_invalid_credentials_audited(client, users, db_session):
    r = client.post("/api/auth/login", json={"username": "admin_t", "password": "WrongPass123"})
    assert r.status_code == 401
    r = client.post("/api/auth/login", json={"username": "nobody", "password": "WrongPass123"})
    assert r.status_code == 401
    actions = _audit_actions(db_session)
    assert actions.count("login_failed") == 2


def test_failed_login_audit_never_contains_password(client, users, db_session):
    from models import AuditLog
    client.post("/api/auth/login", json={"username": "admin_t", "password": "S3cretAttempt!"})
    db_session.expire_all()
    assert all("S3cretAttempt!" not in (a.details or "") for a in db_session.query(AuditLog).all())


def test_login_inactive_user(client, users, db_session):
    users["viewer"].is_active = False
    db_session.commit()
    r = client.post("/api/auth/login", json={"username": "viewer_t", "password": VIEWER_PASSWORD})
    assert r.status_code == 403
    assert "login_denied_disabled" in _audit_actions(db_session)


def test_login_with_legacy_default_password_refused(client, db_session):
    # Simulates a database created by an older version that seeded admin/admin123
    from auth import hash_password
    from models import User
    db_session.add(User(username="admin", email="admin@siem-guardian.local",
                        hashed_password=hash_password("admin123"), role="admin"))
    db_session.commit()
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert r.status_code == 403
    assert "reset-password" in r.json()["detail"]
    assert "access_token" not in r.json()
    assert "login_denied_default_password" in _audit_actions(db_session)


def test_login_sql_injection_attempt_fails(client, users):
    for payload in ["' OR '1'='1", "admin_t' --", "admin_t\" OR \"\"=\""]:
        r = client.post("/api/auth/login", json={"username": payload, "password": "' OR '1'='1"})
        assert r.status_code == 401


def test_login_rate_limited(client, users):
    # LOGIN_RATE_LIMIT_PER_MINUTE=5 in conftest
    codes = [client.post("/api/auth/login", json={"username": "admin_t", "password": "Wrong123x"}).status_code
             for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429


# ═══════════════════════════════════════════════════════════════
# Logs / agent ingestion
# ═══════════════════════════════════════════════════════════════

LOG = {"user": "jsmith", "ip": "192.168.1.10", "event_type": "login", "failed_attempts": 0}


def test_ingest_requires_agent_key(client):
    assert client.post("/api/logs/ingest", json=LOG).status_code == 401
    assert client.post("/api/logs/ingest", json=LOG, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/logs/ingest/batch", json=[LOG]).status_code == 401


def test_ingest_rejected_when_agent_key_not_configured(client, agent_headers):
    with patch("auth.settings.AGENT_API_KEY", ""):
        assert client.post("/api/logs/ingest", json=LOG, headers=agent_headers).status_code == 401


def test_user_token_cannot_ingest(client, auth_headers):
    assert client.post("/api/logs/ingest", json=LOG, headers=auth_headers["admin"]).status_code == 401


def test_ingest_malformed_event_rejected(client, agent_headers):
    for bad in [{**LOG, "ip": "999.1.1.1"}, {**LOG, "ip": "not-an-ip"}, {**LOG, "failed_attempts": -1},
                {**LOG, "event_type": "x" * 51}, {"user": "x"}]:
        assert client.post("/api/logs/ingest", json=bad, headers=agent_headers).status_code == 422, bad


def test_ingest_batch_then_read(client, agent_headers, auth_headers):
    r = client.post("/api/logs/ingest/batch", json=[LOG, {**LOG, "user": "devops"}], headers=agent_headers)
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    logs = client.get("/api/logs/", headers=auth_headers["viewer"]).json()
    assert len(logs) == 2
    assert client.get("/api/logs/count", headers=auth_headers["viewer"]).json()["count"] == 2


def test_get_logs_empty(client, auth_headers):
    assert client.get("/api/logs/", headers=auth_headers["viewer"]).json() == []


def test_get_logs_pagination_bounds(client, auth_headers):
    h = auth_headers["viewer"]
    assert client.get("/api/logs/?skip=0&limit=10", headers=h).status_code == 200
    assert client.get("/api/logs/?limit=100000", headers=h).status_code == 422
    assert client.get("/api/logs/?limit=0", headers=h).status_code == 422
    assert client.get("/api/logs/?skip=-1", headers=h).status_code == 422


def test_get_logs_filter_sql_injection(client, agent_headers, auth_headers):
    client.post("/api/logs/ingest", json=LOG, headers=agent_headers)
    r = client.get("/api/logs/", params={"event_type": "' OR '1'='1"}, headers=auth_headers["viewer"])
    assert r.status_code == 200
    assert r.json() == []  # parameterized: the payload is a literal, matches nothing


# ═══════════════════════════════════════════════════════════════
# Alerts
# ═══════════════════════════════════════════════════════════════

def _make_alert(db_session):
    from models import Alert
    a = Alert(severity="high", message="Synthetic test alert", ip="10.0.0.5", alert_type="brute_force")
    db_session.add(a)
    db_session.commit()
    db_session.refresh(a)
    return a


def test_get_alerts_empty_and_count(client, auth_headers):
    h = auth_headers["viewer"]
    assert client.get("/api/alerts/", headers=h).json() == []
    assert client.get("/api/alerts/count", headers=h).json() == {"active": 0, "total": 0}


def test_get_alerts_invalid_severity(client, auth_headers):
    assert client.get("/api/alerts/?severity=bogus", headers=auth_headers["viewer"]).status_code == 422


def test_viewer_cannot_acknowledge_alert(client, auth_headers, db_session):
    a = _make_alert(db_session)
    r = client.patch(f"/api/alerts/{a.id}/acknowledge", json={"acknowledged": True}, headers=auth_headers["viewer"])
    assert r.status_code == 403


def test_analyst_acknowledges_alert_and_is_audited(client, auth_headers, db_session):
    a = _make_alert(db_session)
    r = client.patch(f"/api/alerts/{a.id}/acknowledge", json={"acknowledged": True}, headers=auth_headers["analyst"])
    assert r.status_code == 200 and r.json()["acknowledged"] is True
    assert client.get("/api/alerts/count", headers=auth_headers["viewer"]).json() == {"active": 0, "total": 1}
    assert "alert_acknowledge" in _audit_actions(db_session)


def test_acknowledge_missing_alert(client, auth_headers):
    r = client.patch("/api/alerts/99999/acknowledge", json={"acknowledged": True}, headers=auth_headers["analyst"])
    assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════
# Network capture / simulator authorization
# ═══════════════════════════════════════════════════════════════

def test_network_capture_authorization(client, auth_headers, agent_headers):
    assert client.post("/api/network/capture?count=5").status_code == 401
    assert client.post("/api/network/capture?count=5", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/network/capture?count=5", headers=auth_headers["viewer"]).status_code == 403
    assert client.post("/api/network/capture?count=5", headers=auth_headers["analyst"]).status_code == 200
    assert client.post("/api/network/capture?count=5", headers=agent_headers).status_code == 200


def test_network_capture_count_bounds(client, auth_headers):
    assert client.post("/api/network/capture?count=100000", headers=auth_headers["analyst"]).status_code == 422


@pytest.mark.parametrize("path", ["/api/simulator/random", "/api/simulator/all"])
def test_simulator_authorization(client, auth_headers, path):
    assert client.post(path).status_code == 401
    assert client.post(path, headers=auth_headers["viewer"]).status_code == 403


# ═══════════════════════════════════════════════════════════════
# WebSocket authentication
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("url", ["/ws", "/ws?token=", "/ws?token=not.a.jwt"])
def test_websocket_rejects_missing_or_invalid_token(client, url):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(url) as ws:
            ws.receive_json()


def test_websocket_rejects_expired_token(client, users):
    from datetime import timedelta
    from auth import create_access_token
    token = create_access_token({"sub": "viewer_t"}, expires_delta=timedelta(seconds=-1))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?token={token}") as ws:
            ws.receive_json()


def test_websocket_accepts_valid_token(client, auth_headers):
    token = auth_headers["viewer"]["Authorization"].split(" ", 1)[1]
    with client.websocket_connect(f"/ws?token={token}") as ws:
        ws.send_text("ping")
        msg = ws.receive_json()
        assert msg["type"] == "pong"


# ═══════════════════════════════════════════════════════════════
# First-run administrator bootstrap
# ═══════════════════════════════════════════════════════════════

def test_env_bootstrap_creates_admin_once(db_session, monkeypatch):
    from bootstrap import bootstrap_admin_from_env
    from models import User
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_USERNAME", "firstadmin")
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_EMAIL", "first@example.com")
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_PASSWORD", "FirstAdm1nPass")
    assert bootstrap_admin_from_env(db_session).username == "firstadmin"

    # Second run with different values must not create another administrator
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_USERNAME", "attacker")
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_EMAIL", "attacker@example.com")
    assert bootstrap_admin_from_env(db_session) is None
    assert [u.username for u in db_session.query(User).filter(User.role == "admin")] == ["firstadmin"]
    assert "admin_bootstrap" in _audit_actions(db_session)


def test_env_bootstrap_rejects_weak_or_default_password(db_session, monkeypatch):
    from bootstrap import bootstrap_admin_from_env
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("SKYLOS_BOOTSTRAP_ADMIN_PASSWORD", "admin123")
    assert bootstrap_admin_from_env(db_session) is None


def test_cli_create_admin_refused_when_admin_exists(users, monkeypatch):
    import manage
    monkeypatch.setenv("SKYLOS_ADMIN_PASSWORD", "AnotherAdm1nPass")
    assert manage.main(["create-admin", "--username", "second", "--email", "second@example.com"]) == 1


def test_cli_reset_password(users, db_session, monkeypatch):
    import manage
    from auth import verify_password
    monkeypatch.setenv("SKYLOS_ADMIN_PASSWORD", "ResetPassw0rd!")
    assert manage.main(["reset-password", "viewer_t"]) == 0
    db_session.expire_all()
    assert verify_password("ResetPassw0rd!", users["viewer"].hashed_password)
    assert "password_reset" in _audit_actions(db_session)

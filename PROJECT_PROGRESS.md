# Skylos — Project Progress

Legacy name: AI-SIEM Guardian. Statuses: NOT STARTED · IN PROGRESS · PARTIAL · NEEDS TESTING · COMPLETE · BLOCKED.
Last updated: 2026-10-05 (source restoration and core integration fixes).

> The previous version of this file marked several items as done that the code did not support
> (for example alert deduplication, a migration strategy, and agent authentication beyond one shared
> key). This version is based on the 2026-10-01 audit: code was read, tests were run and the app was
> exercised against a running server.

---

## Baseline (captured 2026-10-01, before any change this session)

| Item | Result |
|---|---|
| Git | **Not a git repository** (no branch/status available). Earlier handoff said "Git repository initialized"; that is not true of this directory. |
| Python | 3.12 default, 3.11 available. Existing `backend/venv` is a **Python 3.7 venv from another machine** (unusable). |
| `requirements.txt` | **FAIL**: could not install on Python 3.11 (the Docker base image). `scikit-learn<1.1` / `numpy<1.22` have no 3.11 wheels; `email-validator<2` is incompatible with pydantic v2 `EmailStr`. |
| Backend startup | **FAIL**: `ModuleNotFoundError: health_monitor` in the lifespan hook (`database_guardian/monitoring_service.py` used bare imports). The API could not start. |
| Test suite | `pytest.ini` used a `[tool:pytest]` header (ignored), so pytest collected ad-hoc scripts and aborted with INTERNALERROR. `pytest tests`: **61 passed, 3 failed**. Failures were caused by mock pollution: `test_api_routes.py` replaced `fastapi`/`pydantic` in `sys.modules`. |
| Frontend build | **NOT RUN**: Node.js/npm not installed on this machine. |
| Docker | docker CLI 29.7 / compose v5.5 present; **daemon not running, Docker Desktop not installed**. `docker-compose.yml` had `postgres-test` nested under `networks:` (invalid). |
| Lint / type-check | No linters configured. |
| Migrations | None (only `Base.metadata.create_all`). |

### Security findings at baseline (verified by live probes)
1. **CRITICAL**: `POST /api/auth/register` was unauthenticated and accepted `role: "admin"`, so anyone could create an administrator account.
2. **CRITICAL**: default administrator `admin` / `admin123` seeded on startup; documented in the README and pre-filled on the login page.
3. **HIGH**: all log, alert, network and dashboard read endpoints were unauthenticated, and `POST /api/network/capture` was unauthenticated.
4. **HIGH**: agent API key check **failed open** when `AGENT_API_KEY` was unset, and Compose defaulted it to empty. Comparison was not constant-time.
5. MEDIUM: JWT error text echoed to clients. `DEBUG=true` turned on SQL echo with bound parameters (password hashes in logs).
6. MEDIUM: no `.dockerignore`. `backend/Dockerfile` `COPY . .` would bake `siem_guardian.db`, `.env.bak` and venvs into the image.
7. MEDIUM: `CredentialManager` silently generated a random Fernet key when `DB_ENCRYPTION_KEY` was missing or invalid (stored credentials undecryptable after restart) and printed the key in DEBUG. **Resolved in session 3** (SecretProvider; startup fails safely).

---

## Phase A — Foundation

| Feature | Category | Status | Notes / limitations | Files | Tests |
|---|---|---|---|---|---|
| Backend starts | FOUNDATION | COMPLETE | Fixed relative imports. Verified with `uvicorn` + Database Guardian monitoring enabled. | `database_guardian/monitoring_service.py` | `test_app_starts_and_health_ok`, `test_database_guardian_monitoring_module_imports` |
| Python 3.11 dependency set | FOUNDATION | PARTIAL | Installs and runs locally on 3.11. Docker image build NEEDS TESTING. Dev deps split into `requirements-dev.txt`. | `backend/requirements*.txt` | full suite |
| Secret handling | FOUNDATION | PARTIAL | JWT secret required in production; agent key fail-closed; SQL echo off by default. DB credential key validated at startup, never generated or printed (session 3). `.env.development` contains dev-only secrets. `backend/.env.bak` exists (contents not shown; ignored by git and Docker). | `config.py`, `database.py`, `.env.example` | — |
| Administrator initialization | FOUNDATION | PARTIAL | No default admin. `manage.py create-admin` / `reset-password` and env bootstrap (`SKYLOS_BOOTSTRAP_ADMIN_*`), all refused once an admin exists, audited, strength-validated. Legacy `admin123` refused at login. **Missing:** forced password change on first login (schema change; now unblocked by migrations). | `bootstrap.py`, `manage.py`, `main.py`, `auth.py` | bootstrap/CLI tests in `test_api_routes.py` |
| JWT authentication | FOUNDATION | PARTIAL | Signature, expiry, missing-exp, alg=none, foreign-key, deleted/disabled user covered by tests. **Missing:** iss/aud claims, logout/revocation, token-version on password reset. Tokens live in `localStorage`. | `auth.py` | `test_auth.py`, `test_api_routes.py` |
| RBAC (admin/analyst/viewer) | FOUNDATION | PARTIAL | Enforced server-side on every existing route and tested per role. **Missing:** user-management endpoints (list/disable/role change), role management. | `api_routes.py`, `auth.py` | `test_api_routes.py` |
| WebSocket security | FOUNDATION | PARTIAL | Server rejects missing, invalid and expired tokens. UI now sends the JWT and holds one connection across routes, with bounded reconnects. Token remains in the query string; no per-channel permissions. | `main.py`, `auth.py`, `frontend/src/services/websocket.ts` | Existing WS tests (not rerun this session) |
| Rate limiting | FOUNDATION | PARTIAL | Login 5/min per IP verified (429). **Limitation:** keyed on the socket peer, so behind the nginx proxy all users share one IP (shared lockout). In-memory, per process. | `api_routes.py`, `main.py` | `test_login_rate_limited` |
| Input validation | FOUNDATION | PARTIAL | Pagination bounds, severity enum, IP pattern, capture count. IPv6 regex only accepts full 8-group form. | `api_routes.py`, `schemas.py` | `test_api_routes.py` |
| SQL security | FOUNDATION | PARTIAL | ORM queries parameterized; SQLi tests on login + log filter. PostgreSQL database-size query still needs a parameterized query. | `database_guardian/db_connector.py` | Existing SQLi tests (not rerun this session) |
| Error handling | FOUNDATION | PARTIAL | JWT errors sanitized. No global exception handler or structured error logging yet. | `auth.py` | — |
| Security headers | FOUNDATION | PARTIAL | Present on API responses. HSTS is sent even over HTTP; deprecated `X-XSS-Protection`; nginx (frontend) sends none. | `main.py`, `frontend/Dockerfile` | — |
| Audit logging | FOUNDATION | PARTIAL | login, login_failed (with source IP, never the password), disabled/default-password denials, user_created, admin_bootstrap, password_reset, alert_acknowledge, simulate_attack, database registration/update. **Missing:** structured actor/target/result columns and logout. | `api_routes.py`, `bootstrap.py` | Existing audit assertions (not rerun this session) |
| SecretProvider / credential encryption | FOUNDATION | COMPLETE | `SecretProvider` interface (`encrypt`/`decrypt`/`health_check`) + `FernetSecretProvider`, selected by `SECRET_PROVIDER` (only `fernet`). Key validated on first use and at app startup; missing/invalid key fails safely. No key generation or printing. Both Database Guardian call sites use the provider; registration and connection-check routes are now mounted. **Limitations:** no key rotation; Fernet object holds key material in process memory (inherent). | `backend/secret_provider.py`, `database_guardian/credential_manager.py`, `database_guardian/db_connector.py`, `api_routes.py`, `main.py`, `config.py`, `.env.example`, `docker-compose.yml` | `tests/test_secret_provider.py` (existing; not rerun this session) |
| Canonical SecurityEvent model | FOUNDATION | PARTIAL | Migration `0002`, normalizer, and atomic normalization for agent and simulator log ingestion are present. Authenticated `GET /api/events/` now exposes pagination and type/source/time filters. No evidence model or event detail UI yet. | `models.py`, `event_normalizer.py`, `log_processor.py`, `api_routes.py`, `migrations/versions/0002_security_events.py` | Existing test suite not rerun this session |
| Evidence model | FOUNDATION | NOT STARTED | Alerts only carry `log_id`; DB alerts carry inline `evidence_json`. | — | — |
| Database migrations | FOUNDATION | PARTIAL | Startup runs `upgrade head`. Baseline `0001` adopts compatible legacy schemas; `0002` adds `security_events`. SQLite migration history was verified before `0002`; this session did not rerun migrations. **PostgreSQL NEEDS TESTING**. **Limitation:** no lock against two processes migrating at once. | `backend/alembic.ini`, `backend/migrations/`, `backend/database.py`, `tests/conftest.py` | Existing migration tests not rerun this session |
| PostgreSQL (Skylos' own DB) | FOUNDATION | NEEDS TESTING | Needs Docker. Command: `docker compose up -d postgres`, then run backend with `DATABASE_URL=postgresql://...`. | — | — |
| Alert foundation | FOUNDATION | PARTIAL | Alerts are created and broadcast. **No deduplication** (earlier claim incorrect); no explanation fields. | `alert_service.py`, `log_processor.py` | — |
| Incident foundation | FOUNDATION | NOT STARTED | Only an `acknowledged` boolean. | — | — |
| Docker baseline | FOUNDATION | NEEDS TESTING | Fixed: invalid `postgres-test` nesting, required `AGENT_API_KEY`, Postgres bound to 127.0.0.1, healthcheck no longer needs curl, `.dockerignore` added, test DB password from env + profile. `docker compose config` validates. **Not built or started** (no daemon). | `docker-compose.yml`, `*/.dockerignore` | `docker compose config -q` |

## Phase B — Database Guardian

| Feature | Category | Status | Notes |
|---|---|---|---|
| Database Guardian API router | REQUIRED CORE | PARTIAL | Router is mounted. Register/list/detail, update name/active status, alerts, risk score, and a sanitized connection check are available. Supports SQLite and PostgreSQL only. No delete endpoint. |
| Asset registration / inventory | REQUIRED CORE | PARTIAL | API and dashboard page support registration/inventory. `DatabaseAssetOut` does not expose the password. |
| Secure credentials | REQUIRED CORE | PARTIAL | Registration encrypts passwords through SecretProvider and the API never returns them. Password update/re-encryption and key rotation are not built. |
| Connectors (SQLite, PostgreSQL) | REQUIRED CORE | PARTIAL | PostgreSQL database-size lookup is parameterized and connection attempts time out after 5 seconds. SQLite connector still accepts a server-side file path from administrators. |
| Health monitoring | REQUIRED CORE | PARTIAL | Background loop; NEEDS TESTING against Postgres. |
| Login monitoring / brute force | REQUIRED CORE | SIMULATED/PARTIAL | Records **active sessions** from `pg_stat_activity` as successful logins on every 60 s poll (duplicates). No source of **failed** logins (needs PG log parsing), so the brute-force rule can never fire from real telemetry. Alerts are not deduplicated. |
| User / admin / privilege changes | REQUIRED CORE | PARTIAL | `pg_roles` snapshot diff. NEEDS TESTING. |
| Query volume / mass reads / sensitive access / exports | REQUIRED CORE | PARTIAL | `pg_stat_user_tables` heuristics. NEEDS TESTING. |
| Schema monitoring | REQUIRED CORE | PARTIAL | NEEDS TESTING. |
| Backup monitoring | REQUIRED CORE | PARTIAL | Reads only Skylos' own `database_backups` table; nothing populates it. |
| Out-of-hours, source anomalies, config changes, audit-log tampering, file integrity, maintenance windows | REQUIRED CORE / ENGINE-SPECIFIC | NOT STARTED | — |
| Risk scoring | REQUIRED CORE | PARTIAL | Weights match spec. **Missing:** 10-minute window, 30-min/+40 category cap, dedup, correlation bonus, severity bands, maintenance exclusions, stored explanations. Score capped at 100 (spec has no cap). |
| DB alerts / timeline / reporting | REQUIRED CORE | NOT STARTED / PARTIAL | Alerts exist without dedup; no timeline or reports. |

## Phase C — Agents

| Feature | Status | Notes |
|---|---|---|
| Agent authentication | PARTIAL | Single shared `AGENT_API_KEY` (now fail-closed, constant-time). **No per-agent identity**, registration, approval, revocation or rotation. |
| System log agent | SIMULATED | Generates random synthetic logs; does not read real OS logs. |
| Network agent | SIMULATED | Asks the **backend** to run a capture; the backend simulates traffic unless `ENABLE_REAL_CAPTURE=true`. Not a device-side collector. |
| Offline queue | PARTIAL | JSON file cache. Verified live: **auth failures (401) are treated as offline**, so events with a bad key are cached and retried forever. No event IDs, so no dedup on resend. No size bound. Non-atomic writes. |
| Heartbeat, health, versioning, grouping, config | NOT STARTED | — |

## Phase D — Detection & Incidents

| Feature | Status | Notes |
|---|---|---|
| Isolation Forest | PARTIAL | Works; tests pass. **Concerns:** retrains automatically every 50 ingested logs on untrusted agent data; `hour_of_day` uses ingestion time; no model versioning; anomaly score not stored. |
| Rule engine | PARTIAL | Fallback thresholds only. |
| Attack simulator | SIMULATED | Simulated logs are stored as ordinary logs with **no simulated flag**, so they are indistinguishable from real telemetry (violates spec §64/§68). |
| Dedup, correlation, MITRE mapping, false-positive tracking, incidents | NOT STARTED | — |

## Phase E — Frontend

| Feature | Status | Notes |
|---|---|---|
| Build | PARTIAL | `npm ci` and `npm run build` succeeded with Node 22.22.1; pages are split into route chunks. Browser runtime still needs a live API session. | `frontend/package.json`, `frontend/package-lock.json` |
| Dependency audit | COMPLETE | `npm audit fix` updated compatible packages; `npm audit` reported zero vulnerabilities afterward. | `frontend/package-lock.json` |
| Login | PARTIAL | Default credentials removed; a 401 from the login endpoint now stays on the form so the error is visible. Built successfully; live login flow not exercised. |
| Real-time alerts | PARTIAL | WebSocket now authenticates with the stored JWT and stays connected across dashboard pages. Built successfully; live socket flow not exercised. |
| Database Guardian | PARTIAL | New role-aware database page covers registration, connection checks, monitoring toggle, risk score, and recent alerts. Built successfully. | `frontend/src/pages/Databases.tsx` |
| Incidents, user management, agent pages | NOT STARTED | — |

## Phase F — Desktop (Tauri): NOT STARTED (Rust not installed)
## Phase G — Deployment / docs: `RUNNING_SKYLOS.md` NOT STARTED; backup/restore/upgrade docs NOT STARTED.

---

## Known pre-existing issues (not caused by this session)
- `backend/venv` (Python 3.7, foreign path) is unusable. Left in place; use `backend/.venv`.
- Ad-hoc scripts in `backend/` (`init_test.py`, `test_basic.py`, `test_security*.py`, `verify_phase2.py`) and `debug_import.py` at the root are not part of the test suite. `verify_phase2.py` imports a name that does not exist (`credential_manager`).
- `.claude/worktrees/` contains other worktrees, one with unrelated content. Not inspected or modified.

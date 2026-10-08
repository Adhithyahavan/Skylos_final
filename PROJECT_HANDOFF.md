# Skylos — Session Handoff

## Session: 2026-10-05 — Restore and wire core project flows

### What changed
- Restored the backend and frontend source directories into the project root from the available latest source snapshot. Virtual environments, database files, local secret files, `node_modules`, and generated frontend output were excluded.
- The recovered source already contained Alembic migration `0002`, the canonical `SecurityEvent` model, the normalizer, and transactional agent/simulator ingestion. Added authenticated `GET /api/events/` with pagination and type/source/time filters.
- Mounted the Database Guardian router and imported its models. Added admin update and admin/analyst connection-check endpoints; database registration now accepts only the implemented SQLite and PostgreSQL connectors. Made registration and its audit record one transaction, and fixed duplicate risk-score response fields.
- Added a Database Guardian dashboard page for registration, monitoring toggles, connection checks, risk scores, and recent alerts.
- Fixed the WebSocket client to send the JWT and stay connected across dashboard pages with safe reconnect handling. A failed login no longer triggers the global 401 redirect before its error can be displayed.
- Fixed the PostgreSQL size query parameterization and added a five-second connection timeout. Patched the frontend dependency tree to zero reported npm advisories, set compatible version floors, and lazy-loaded route pages.
- `.gitignore` now excludes `.env.*` while allowing `.env.example`.

### Verification status
- `npm ci` and `npm run build` succeeded with Node 22.22.1. The production bundle has route-level chunks; the main bundle is about 290 kB and the dashboard chunk about 368 kB before gzip.
- `npm audit fix` resolved the reported compatible dependency advisories; `npm audit` then reported zero vulnerabilities.
- The backend Python source passed AST syntax parsing. A runtime import smoke check could not run because the active Python 3.14 installation lacks the backend dependency `slowapi`; no backend tests were run.
- Docker/PostgreSQL runtime status and live browser/API flows were not checked.
- Before deployment, install the backend requirements under Python 3.11, run the documented backend suite, and exercise the compose stack with configured secrets.

### Still incomplete
- Incident management, per-agent identity and lifecycle, evidence storage, event detail UI, database credential rotation, richer database telemetry, full risk-score specification, and desktop client remain unfinished. See `PROJECT_PROGRESS.md`.
- The 2026-10-01 entries below are historical; this 2026-10-05 session supersedes their application-state and next-action notes.

---

## Session: 2026-10-01 (3) — SecretProvider (Next action from session 2)

### Inspection before changes
- `CredentialManager` stored **raw Fernet tokens** in `database_assets.encrypted_password`.
- If `DB_ENCRYPTION_KEY` was missing or invalid, it silently generated a random key (stored credentials lost at the next restart) and printed it in DEBUG.
- Callers: `api_routes.register_database` (encrypt) and `PostgreSQLConnector.__init__` (decrypt).
- The real `siem_guardian.db` has no `database_assets` rows (no table), so no existing ciphertext needed migrating. No key was configured in `.env.development` or `backend/.env.bak`.

### What changed
- **New `backend/secret_provider.py`:**
  - `SecretProvider` ABC (`encrypt`, `decrypt`, `health_check`) and `FernetSecretProvider`.
  - `build_secret_provider` / `get_secret_provider` (lazy singleton) / `reset_secret_provider` / `validate_secret_provider`.
  - Errors: `SecretProviderConfigError` and `SecretDecryptionError`, with fixed sanitized messages raised `from None`.
  - No key generation or printing. The key string is not stored on the provider, and `repr` hides key material.
- **Same token format** as before, so values encrypted under a given key still decrypt with that key (tested with a token produced the old way).
- **All Database Guardian credential crypto goes through the provider:**
  - `api_routes.register_database` and `db_connector.PostgreSQLConnector` call it directly.
  - `database_guardian/credential_manager.py` is now a delegating shim with no Fernet.
- **Startup fails safely.** `main.py` lifespan calls `validate_secret_provider()` before migrations. A missing or invalid key gives a CRITICAL "Configuration error: …" log and the app refuses to start. Validation is deliberately **not** in `config.py` import, so `alembic` and `manage.py` keep working without the key.
- **Config:** `SECRET_PROVIDER` (default `fernet`) in `config.py`.
- **`.env.example`:** `SECRET_PROVIDER` added, and `DB_ENCRYPTION_KEY` documented as required, with generation, backup and do-not-change guidance.
- **Compose:** `DB_ENCRYPTION_KEY` is required (`:?`) and `SECRET_PROVIDER` is passed through.
- **Docs:** README quick start and SETUP_GUIDE now list the key as required.

### Files changed
- New: `backend/secret_provider.py`, `tests/test_secret_provider.py`.
- Modified: `backend/main.py`, `backend/config.py`, `backend/api_routes.py` (encrypt call only), `backend/database_guardian/db_connector.py` (decrypt call only), `backend/database_guardian/credential_manager.py`, `tests/conftest.py` (per-session test key), `.env.example`, `docker-compose.yml`, `README.md`, `SETUP_GUIDE.txt`, `PROJECT_PROGRESS.md`, `PROJECT_HANDOFF.md`.

### Migrations / dependencies
None. `cryptography` was already a dependency.

### Tests executed (actually run)
- `backend\.venv\Scripts\python.exe -m pytest tests/test_secret_provider.py`: **35 passed**. Covers:
  - valid key;
  - missing key (`""`, whitespace, `None`), with no fallback generation and nothing printed;
  - 5 invalid keys, with no value echo and no exception chaining;
  - unsupported provider;
  - round-trips (empty, unicode, 4 KB, SQL-like);
  - randomized ciphertext;
  - tampered/garbage ciphertext;
  - restart persistence with the same key via DB + connector;
  - restart with a different key, failing sanitized;
  - legacy CredentialManager token compatibility;
  - shim delegation;
  - app startup refused on missing/invalid key, with the key absent from the exception, logs, stdout and stderr;
  - successful startup never logs the key.
- Full suite: **170 passed, 0 failed** (135 → 170). 81 warnings, all pre-existing kinds (extra TestClient instances).
- **Real processes** (scratchpad SQLite):
  - `uvicorn` with no key → exit 3 with a sanitized CRITICAL message.
  - Invalid key → exit 3, and the invalid value appears 0 times in the output.
  - Valid key → healthy, and the key appears 0 times in the output.
  - Process A stored an encrypted credential. The DB file holds only a Fernet token, never the plaintext.
  - Separate process B (same key) decrypted it through `create_connector`.
  - Process C (different key) got a sanitized `SecretDecryptionError`.
- `docker compose config`: errors clearly without `DB_ENCRYPTION_KEY`, valid with it. **Static check only; Compose not run.**

### Behaviour change to note
Every backend start now requires a valid `DB_ENCRYPTION_KEY`, including local development. Generate one with the command in `.env.example` and keep it. Changing or losing it makes stored database credentials unreadable; they must then be re-entered.

### Still NEEDS TESTING (unchanged)
- PostgreSQL migration verification (Docker/PostgreSQL unavailable). Not claimed complete.
- Docker build/run, frontend build.

### Known limitations
- No key rotation yet (MultiFernet with old and new keys plus a re-encryption job).
- The encrypt call site lives in the still-unmounted Database Guardian router (Phase B), so API registration is not exercised yet.
- The decrypted DB password lives on the connector object while it exists (needed to connect).

### Blockers
Environment only: Node.js, Docker daemon, Rust.

---

## Session: 2026-10-01 (2) — Alembic migrations (Next action from session 1)

### What changed
- **Alembic introduced.** `backend/alembic.ini`, `backend/migrations/env.py`, `script.py.mako`, `versions/0001_baseline.py`.
- **Baseline `0001`** was generated from `models.py` with autogenerate, then made idempotent and frozen (it does not import `models.py`):
  - creates each baseline table/index only if absent;
  - verifies pre-existing tables have every baseline column, and aborts with an explanation and no changes otherwise;
  - downgrade raises (dropping adopted legacy tables would destroy data the migration never created).
- **Startup is migration-aware.** `database.init_db()` now calls `run_migrations()` (`alembic upgrade head` on the app engine) instead of `create_all`. `main.py` and `manage.py` are unchanged because they already call `init_db()`.
- **`env.py`** takes the caller's connection, never stores the DB URL in config, and only configures logging under the alembic CLI. This avoids resetting app logging.
- **Tests build their schema through migrations.** `tests/conftest.py` now uses migrations, so tests catch a model change without a migration.
- **Docs:** README "Database Migrations" section.

### Design note: "stamp existing, upgrade empty"
The handoff asked to stamp existing databases and upgrade empty ones. Real legacy databases can be **partial**: the actual `siem_guardian.db` has only 5 of 17 tables, because it predates Database Guardian. A plain `stamp` would have marked it current while 12 tables were missing. The idempotent baseline covers both cases in one path, `upgrade head`. Empty databases get the full schema. Legacy databases keep their tables and data, gain what's missing, and are recorded at `0001`.

### Files changed
New: `backend/alembic.ini`, `backend/migrations/{env.py,script.py.mako,versions/0001_baseline.py}`, `tests/test_migrations.py`.
Modified: `backend/database.py`, `backend/requirements.txt` (`alembic>=1.16,<2.0`), `tests/conftest.py`, `README.md`, `PROJECT_PROGRESS.md`, `PROJECT_HANDOFF.md`.

### Migrations created
`0001` baseline (head). No other revisions.

### Dependencies added
`alembic` 1.20.0 (MIT, maintained by the SQLAlchemy project; runtime dependency because startup runs migrations).

### Tests executed (actually run)
- `backend\.venv\Scripts\python.exe -m pytest` (repo root): **135 passed, 0 failed** (128 previous + 7 migration tests). Warning count is back to the 78 pre-existing ones.
- `tests/test_migrations.py` covers:
  - single head;
  - empty DB → head with **zero diff vs `models.py`** (`compare_metadata`);
  - legacy 5-table DB (exact real DDL, synthetic rows) adopted with data preserved;
  - full `create_all` DB adopted;
  - idempotent re-runs;
  - incompatible legacy schema refused with no changes;
  - downgrade refused.
- Negative check: dropping an index produces a non-empty diff, so the sync guard is not vacuous.
- **Real-system check:** started `uvicorn main:app` on a scratchpad **copy** of the real `backend/siem_guardian.db`.
  - Upgrade ran at startup and the server came up healthy.
  - Tables went from 5 to 17 (+ `alembic_version`).
  - Row counts were identical before and after (users 1, logs 865, alerts 215, network_activity 10300, audit_logs 6).
  - `alembic current` prints `0001 (head)`.
  - App logging continued after the migration.
  - Legacy `admin/admin123` login is still refused (403).
  - The original DB's checksum is unchanged.

### Not verified
- PostgreSQL upgrade: no Docker daemon. Steps are recorded in `PROJECT_PROGRESS.md` (Database migrations row).

### Known limitations
- No migration lock: two backend processes starting at the same moment could race. Run one process when upgrading. A future option is a PostgreSQL advisory lock in `run_migrations`.
- `config.validate()` prints warnings to stdout, which also appear in `alembic` CLI output (pre-existing, cosmetic).
- The real `backend/siem_guardian.db` was **not** migrated; only a copy was. It will be upgraded automatically the next time the backend starts against it. Back it up first.

### Blockers
Unchanged: Node.js, Docker daemon and Rust are absent (environment only).

Next action: superseded by session 3.

---

## Session: 2026-10-01 — Audit, baseline, critical auth/RBAC hardening

### What changed
1. **Backend startup fixed.** `database_guardian/monitoring_service.py` used bare imports and crashed the lifespan hook, so the API could not start at all.
2. **Dependencies installable on Python 3.11** (the Docker base). Pins updated; `bcrypt==4.0.1` pinned for passlib compatibility; `email-validator>=2` for pydantic v2. Test deps moved to `backend/requirements-dev.txt`.
3. **Closed open admin self-registration.** `POST /api/auth/register` now requires an administrator (path unchanged for API compatibility).
4. **Removed the default `admin/admin123` account.** New first-run bootstrap: `python manage.py create-admin` or `SKYLOS_BOOTSTRAP_ADMIN_*` env vars. Both are refused once an active admin exists, strength-validated and audited. `manage.py reset-password` for recovery. Logins using the legacy default password are refused with reset instructions; nothing in existing databases is modified.
5. **Authentication on all read endpoints** (logs, alerts, network, dashboard). `POST /api/network/capture` now requires the agent key or the analyst/admin role. Pagination and enum bounds added.
6. **Agent key fails closed** when unset; constant-time comparison.
7. JWT errors no longer echo library text. SQL echo decoupled from `DEBUG` (`SQL_ECHO`, default false). `DB_GUARDIAN_MONITORING_ENABLED` switch added.
8. **Audit logging**: failed logins carry the source IP (never the password); new events for user creation, bootstrap, password reset, disabled/default-password denials.
9. **Docker Compose**: fixed the invalid `postgres-test` nesting (now under `services`, `guardian-test` profile, password from env). `AGENT_API_KEY` is required. Postgres is published on 127.0.0.1 only. The backend healthcheck no longer needs curl (absent in the slim image, which would have stopped agents from ever starting). Added `.dockerignore` files so the DB, `.env*` and venvs stay out of images.
10. **Tests rewritten to run against the real app.** `test_auth.py` and `test_api_routes.py` previously replaced `fastapi`/`pydantic` in `sys.modules`. Their scenarios are kept and the security matrix added. `tests/conftest.py` pins config and uses a temp SQLite DB. `pytest.ini` header fixed.

### Architecture changes
- New module `backend/bootstrap.py` (admin bootstrap/reset) and CLI `backend/manage.py`.
- New dependency helper `auth.require_agent_or_role(*roles)`.
- No schema changes and no migrations created.

### Files changed
Backend: `api_routes.py`, `auth.py`, `main.py`, `config.py`, `database.py`, `database_guardian/monitoring_service.py`, `requirements.txt`; new `bootstrap.py`, `manage.py`, `requirements-dev.txt`, `.dockerignore`.
Tests: `tests/conftest.py` (new), `tests/test_auth.py`, `tests/test_api_routes.py` (rewritten), `pytest.ini`.
Frontend: `src/pages/Login.tsx` (removed pre-filled default credentials; branding "Skylos"), new `.dockerignore`.
Config/docs: `docker-compose.yml`, `.env.example`, `.gitignore`, `README.md`, `SETUP_GUIDE.txt`, `PROJECT_PROGRESS.md`, `PROJECT_HANDOFF.md`.

### Dependencies added
`pytest-asyncio`, `httpx` (dev only). No new runtime dependencies (`bcrypt` was already pulled in by `passlib[bcrypt]`; it is now pinned).

### Tests executed (all actually run)
- `backend\.venv\Scripts\python.exe -m pytest` (repo root): **128 passed, 0 failed**. Baseline was 61 passed, 3 failed.
- Live server (`uvicorn main:app --port 8765`, scratch SQLite DB, monitoring enabled): startup OK, no tracebacks. Anonymous `GET /api/logs/` → 401. Anonymous admin registration → 401. CLI bootstrap OK; second bootstrap refused (exit 1). Admin login OK. Real `agent/system_log_agent.py` ingests with the correct key and is rejected with a wrong key. Network capture with the agent key → 200. Simulator → 80 logs, 49 alerts. WebSocket with a valid token → pong; with a bad token → rejected.
- `docker compose config -q`: valid with required vars; fails clearly without them.

### Not verified (environment)
- Frontend build: Node.js not installed. `Login.tsx` edit is uncompiled.
- Docker build/run and PostgreSQL: Docker daemon not available.

### Current application state
The backend runs locally on SQLite with authenticated, role-checked endpoints. The Database Guardian API is still unmounted/broken. Real-time UI updates are still broken: the frontend WebSocket sends no token.

### Known limitations / unresolved
See `PROJECT_PROGRESS.md`. Most important open security items:
- Fernet key random fallback in `CredentialManager`.
- Rate limit keyed on the proxy IP behind nginx.
- No token revocation.
- Simulated logs not flagged as simulated.
- Isolation Forest auto-retrains on untrusted telemetry.

### Blockers
- Node.js absent → frontend build untestable.
- Docker daemon absent → Compose/PostgreSQL untestable.
- Rust absent → Tauri untestable.
These are environment blockers, not code blockers.

### Remaining work (dependency order)
1. Migrations (Alembic) with a baseline revision.
2. SecretProvider plus the key-fallback fix.
3. Canonical SecurityEvent and evidence model.
4. Database Guardian vertical slice: mount the router, connectivity test, PG log-based login telemetry, dedup, spec-compliant risk scoring.
5. Frontend WebSocket token.
6. Agent identity and registration.
7. Incidents.
8. Frontend pages.
9. Desktop.
10. `RUNNING_SKYLOS.md`.

(Superseded by the session above.)

---

**Next action: `Define the canonical SecurityEvent model: add a security_events table (event_id, event_type, timestamp, ingestion_timestamp, source_type, source_id, asset_id, device_id, actor, actor_type, source_address, destination_address, action, object_type, object_name, outcome, severity_hint, raw_event_reference, attributes JSON, correlation_key) via Alembic migration 0002, add a normalizer that converts agent log ingestion (POST /api/logs/ingest[/batch]) into SecurityEvent rows alongside the existing Log rows without changing the API contract, and add tests (migration, normalization, malformed input, ingestion end-to-end).`**

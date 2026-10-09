# Running Skylos

Skylos (legacy name: AI-SIEM Guardian) is a security monitoring platform: a FastAPI backend, a React
dashboard, log/network agents, and a Database Guardian that watches registered SQLite and PostgreSQL
databases. This guide explains how to install, run, test, stop and troubleshoot it.

**What has and has not been verified.** Every command marked ✅ was run while writing this guide
(Linux, Python 3.11, Node 22). Commands marked ⚠️ are documented from the repository's configuration
but were **not run** (Docker daemon, Windows, Tauri). The desktop (Tauri) client does not exist yet.

---

## 1. What you need

| Tool | Why | Version used | Get it | Check | Cost |
|---|---|---|---|---|---|
| Git | get the code | any recent | https://git-scm.com | `git --version` | free |
| Python | backend, agents | **3.11** (the Docker image uses 3.11; 3.12/3.13 untested) | https://www.python.org | `python --version` | free |
| Node.js + npm | dashboard | 22 (`package.json` needs `^20.19.0 \|\| >=22.12.0`) | https://nodejs.org | `node --version` | free |
| Docker Desktop / Engine + Compose | full stack, PostgreSQL | 29.x | https://www.docker.com | `docker compose version` | free for personal/small use; check Docker's licence for larger companies |
| Npcap (Windows) / libpcap (Linux/macOS) | **optional**, real packet capture only | — | https://npcap.com | — | Npcap is free for personal use; commercial use needs a licence |
| Rust + Tauri prerequisites | desktop client | — | https://tauri.app | `rustc --version` | free — **not needed yet, no desktop client exists** |

Ports: backend `8000`, dashboard dev server `5173` (Docker: `80`), PostgreSQL `5432` (bound to
`127.0.0.1` only). Internet access is only needed to install dependencies. RAM/disk are not
benchmarked; the Python machine-learning dependencies (scikit-learn, numpy) alone take several hundred
MB of disk, so leave a few GB free. Treat that as an estimate, not a requirement.

## 2. Get the code and configure it

```bash
git clone https://github.com/Adhithyahavan/Skylos_final.git
cd Skylos_final
cp .env.example .env          # Windows PowerShell: Copy-Item .env.example .env
```

Edit `.env`. Never commit it, and use different secrets for each environment. Generate values with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"                              # JWT_SECRET_KEY, AGENT_API_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" # DB_ENCRYPTION_KEY
```

| Variable | Required | Meaning |
|---|---|---|
| `JWT_SECRET_KEY` | yes | signs login tokens (≥ 32 characters) |
| `AGENT_API_KEY` | yes | shared key agents send; agents are rejected when empty |
| `DB_ENCRYPTION_KEY` | **yes** | Fernet key protecting stored database credentials. The backend refuses to start without a valid one. **Back it up separately from the database; losing or changing it makes stored credentials unreadable.** |
| `DATABASE_URL` | yes | `sqlite:///./siem_guardian.db` for local development, or the PostgreSQL URL |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Docker | credentials for the bundled PostgreSQL |
| `CORS_ORIGINS` | yes | comma-separated dashboard origins, e.g. `http://localhost:5173` |
| `SKYLOS_BOOTSTRAP_ADMIN_USERNAME/EMAIL/PASSWORD` | first start | creates the first administrator, only while none exists |
| `DB_GUARDIAN_MONITORING_ENABLED` | no | `true` starts the background database monitors |
| `DB_MONITOR_HEALTH_INTERVAL`, `DB_MONITOR_LOGIN_INTERVAL`, `DB_MONITOR_QUERY_INTERVAL` | no | monitor intervals in seconds |
| `ENABLE_REAL_CAPTURE`, `CAPTURE_INTERFACE`, `PACKET_COUNT` | no | real packet capture (needs Npcap/libpcap and privileges); off = simulated traffic |
| `SMTP_*`, `ALERT_EMAIL_TO` | no | email alerts |

There is **no default administrator**. Anything previously using `admin` / `admin123` is refused at login.

## 3. Run locally without Docker (SQLite) ✅

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate      # PowerShell: py -3.11 -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt                        # runtime + test dependencies
export DATABASE_URL=sqlite:///./siem_guardian.db           # PowerShell: $env:DATABASE_URL="sqlite:///./siem_guardian.db"
# JWT_SECRET_KEY, AGENT_API_KEY, DB_ENCRYPTION_KEY must also be set (environment or backend/.env)
python manage.py create-admin --username admin --email admin@example.com   # prompts for a password
uvicorn main:app --port 8000
```

Migrations run automatically at start-up. Check it: `curl http://localhost:8000/api/health` should
return `{"status":"healthy",...}`. Interactive API docs are served at `/docs` (they are not disabled in production yet).

Dashboard (second terminal):

```bash
cd frontend
npm ci
npm run dev          # open http://localhost:5173
```

Log in with the administrator you created. Production build: `npm run build` ✅.

Agents (third terminal, optional; both use `BACKEND_URL` and `AGENT_API_KEY`):

```bash
cd backend
python agent/system_log_agent.py     # SIMULATED: generates synthetic logs
python agent/network_agent.py        # asks the backend to capture; simulated unless ENABLE_REAL_CAPTURE=true
```

Stop any component with `Ctrl+C`.

## 4. Run with Docker Compose ⚠️ (configuration validated, stack not started)

```bash
docker compose config -q          # validates .env (fails clearly if a required variable is missing)
docker compose up --build -d
docker compose ps
docker compose logs -f backend
curl http://localhost:8000/api/health
docker compose down               # stop (data volumes are kept)
```

Dashboard: `http://localhost:80` (`FRONTEND_PORT` changes it). Create the first administrator with
`docker compose exec backend python manage.py create-admin --username <name> --email <email>` or the
`SKYLOS_BOOTSTRAP_ADMIN_*` variables. PostgreSQL is published on `127.0.0.1` only; do not expose it publicly.

Synthetic Database Guardian target (a separate PostgreSQL 14, profile `guardian-test`, port 5433, data
volume `postgres-test-data`): set `GUARDIAN_TEST_DB_PASSWORD`, then
`docker compose --profile guardian-test up -d postgres-test`.

## 5. First run checklist

1. Log in as the administrator; create analyst and viewer users (administrators only).
2. **Database Guardian** page → register a database (SQLite path or PostgreSQL host/port). The password is
   encrypted on the server and never shown again. Use **Test connection**.
3. **Risk and alerts** shows the score, severity (Low 0–19, Medium 20–39, High 40–69, Critical 70+)
   and *why* — each rule, its points, reasons and evidence references.
4. Start an agent and confirm logs appear on **System Logs**; use **Threat Alerts → Simulate Attack** and
   confirm alerts arrive live (authenticated WebSocket).

## 6. Database Guardian risk scoring

| Event | Points |
|---|---|
| 3–4 failed logins in 10 min / 5–9 / 10+ | +5 / +15 / +25 |
| Unapproved new administrator | +25 |
| Unapproved privilege escalation | +30 |
| Disabled/tampered audit logging | +40 |
| Missing required backup / failed backup verification | +20 / +25 |
| Unapproved schema change | +5 |
| Unusual sensitive-data access | +15 |
| Large/unapproved export | +30 |
| Suspicious out-of-hours access / unknown or untrusted source | +5 / +10 |
| Related suspicious events (2+ categories) within 30 min | +15 |

The same event is counted once; the same rule for the same actor/source/object counts once per 30
minutes; each category is capped at +40 per 30 minutes; the total is not capped. Acknowledged alerts
stop counting. **Approval workflows do not exist yet**, so every such event is treated as unapproved.
Maintenance windows are configured by an administrator (`PATCH /api/databases/{id}` with
`maintenance_windows`; each has `start`, `end`, `categories`, `multiplier` where `0` excludes and
`0.5` halves the points). Excluded events remain visible in the explanation. Stored snapshots:
`GET /api/databases/{id}/risk-history`.

**Telemetry limits (what is real, what is not).** PostgreSQL role changes, schema and statistics are
read from system catalogues; "logins" currently come from `pg_stat_activity` (current sessions, not
failed attempts), so brute-force detection cannot fire from real PostgreSQL telemetry yet. Backup
monitoring reads Skylos's own backup table, which nothing populates. Out-of-hours, source anomalies,
audit-log tampering and file integrity are not implemented. The attack simulator and agents produce
**simulated** data; simulated records are not yet flagged as such in storage.

## 7. Tests ✅

```bash
cd Skylos_final                                  # repository root
python -m pytest                                 # needs backend/requirements-dev.txt installed
cd frontend && npm run build                     # type-check + production build
```

Tests use synthetic data and a temporary SQLite database; they never touch your real database.
PostgreSQL integration tests do not exist yet.

## 8. Backup and restore

* **SQLite:** stop the backend, copy the `.db` file. Restore by copying it back.
* **PostgreSQL (Docker)** ⚠️: `docker compose exec postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > skylos.sql`;
  restore into an empty database with `docker compose exec -T postgres psql -U "$POSTGRES_USER" "$POSTGRES_DB" < skylos.sql`.
* Always back up `DB_ENCRYPTION_KEY` separately; without it stored database credentials must be re-entered.
* **Upgrades:** back up first. Migrations apply on start; downgrading below the baseline is unsupported
  (restore the backup instead). Run one backend process while upgrading.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| Backend exits with "Configuration error" | `DB_ENCRYPTION_KEY` missing/invalid; regenerate for a new install, never replace the key of an existing install |
| `ModuleNotFoundError` | wrong Python or dependencies not installed in the active virtual environment (use 3.11) |
| `docker compose` complains a variable is unset | `.env` is missing `POSTGRES_PASSWORD`, `JWT_SECRET_KEY`, `AGENT_API_KEY` or `DB_ENCRYPTION_KEY` |
| Login refused with a default-password message | reset with `python manage.py reset-password <username>` |
| Login returns 429 | login is limited to 5/minute per address; wait one minute |
| Dashboard shows no live alerts | the WebSocket needs a valid token (`/ws?token=<JWT>`); log in again |
| Browser CORS errors | add the dashboard origin to `CORS_ORIGINS` |
| Agent events rejected (401) | `AGENT_API_KEY` differs between agent and backend |
| Database shows *offline* | use **Test connection**; verify host/port/credentials and network reachability from the backend |
| Real packet capture fails | install Npcap/libpcap and run with the required privileges, or leave `ENABLE_REAL_CAPTURE=false` |
| Port already in use | change `FRONTEND_PORT`/`POSTGRES_PORT` or stop the other program |

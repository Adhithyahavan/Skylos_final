"""
AI-SIEM Guardian — API Routes
REST endpoints for logs, alerts, network activity, dashboard stats, auth, and attack simulation.
"""

import json
from datetime import datetime, timezone
from typing import Optional, List, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Header, Request
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from slowapi import Limiter
from slowapi.util import get_remote_address

from database import get_db
from models import (
    User, Log, Alert, NetworkActivity, AuditLog, DatabaseAsset, DatabaseAlert,
    DatabaseRiskSnapshot, SecurityEvent,
)
from schemas import (
    UserCreate, UserLogin, UserOut, Token,
    LogCreate, LogOut,
    AlertOut, AlertAcknowledge,
    NetworkActivityCreate, NetworkActivityOut,
    DashboardStats, TimelineEvent,
    DatabaseAssetCreate, DatabaseAssetUpdate, DatabaseAssetOut,
    DatabaseHealthOut, DatabaseAlertOut,
    DatabaseActivityStats, DatabaseRiskScoreBreakdown, DatabaseRiskSnapshotOut,
    SecurityEventOut,
)
from auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_role, validate_password_strength, verify_agent_key,
    require_agent_or_role, LEGACY_DEFAULT_PASSWORDS,
)
from config import settings
from log_processor import process_log, process_logs
from event_normalizer import EventNormalizationError, agent_source, simulator_source
from network_analyzer import network_analyzer
from attack_simulator import run_random_attack, run_all_attacks

# ── Rate Limiter ────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, config_filename="")

# ── Router instances ────────────────────────────────────────────
auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])
logs_router = APIRouter(prefix="/api/logs", tags=["Logs"])
alerts_router = APIRouter(prefix="/api/alerts", tags=["Alerts"])
network_router = APIRouter(prefix="/api/network", tags=["Network"])
dashboard_router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])
simulator_router = APIRouter(prefix="/api/simulator", tags=["Attack Simulator"])
database_router = APIRouter(prefix="/api/databases", tags=["Database Guardian"])
events_router = APIRouter(prefix="/api/events", tags=["Security Events"])


# ═══════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@auth_router.post("/register", response_model=UserOut)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
def register(
    request: Request,
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """
    Create a new user. Administrator only — there is no public self-registration.
    The first administrator is created with `python manage.py create-admin`
    or the SKYLOS_BOOTSTRAP_ADMIN_* environment variables.
    """
    # Validate password strength
    is_valid, error_msg = validate_password_strength(user.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Check if username already exists
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.query(User).filter(User.email == user.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
        role=user.role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="user_created",
        details=f"Admin {current_user.username} created user {db_user.username} (id={db_user.id}) with role {db_user.role}"
    )
    db.add(audit)
    db.commit()

    return db_user


@auth_router.post("/login", response_model=Token)
@limiter.limit(f"{settings.LOGIN_RATE_LIMIT_PER_MINUTE}/minute")
def login(request: Request, credentials: UserLogin, db: Session = Depends(get_db)):
    """Authenticate and return a JWT token."""
    source_ip = get_remote_address(request)
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        # Audit failed login attempt (never record the submitted password)
        audit = AuditLog(
            user_id=user.id if user else None,
            action="login_failed",
            details=f"Failed login attempt for username: {credentials.username} from {source_ip}"
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        db.add(AuditLog(
            user_id=user.id,
            action="login_denied_disabled",
            details=f"Login attempt for disabled account {user.username} from {source_ip}"
        ))
        db.commit()
        raise HTTPException(status_code=403, detail="Account is disabled")

    if credentials.password in LEGACY_DEFAULT_PASSWORDS:
        db.add(AuditLog(
            user_id=user.id,
            action="login_denied_default_password",
            details=f"Login refused for {user.username} from {source_ip}: legacy default password still set"
        ))
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="This account uses a known default password. An administrator must reset it "
                   "with: python manage.py reset-password <username>",
        )

    token = create_access_token(data={"sub": user.username, "role": user.role})

    # Audit log
    audit = AuditLog(user_id=user.id, action="login", details=f"User {user.username} logged in from {source_ip}")
    db.add(audit)
    db.commit()

    return Token(access_token=token, role=user.role, username=user.username)


@auth_router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the current authenticated user."""
    return current_user


# ═══════════════════════════════════════════════════════════════
# LOG ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@logs_router.post("/ingest", response_model=LogOut)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def ingest_log(request: Request, log: LogCreate, db: Session = Depends(get_db), x_api_key: Optional[str] = Header(None)):
    """
    Ingest a single log entry.
    Runs through the full processing pipeline (enrichment → AI → alerting).
    Requires valid agent API key in X-API-Key header.
    """
    # Verify agent API key
    if not verify_agent_key(x_api_key or ""):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing agent API key. Include X-API-Key header."
        )

    try:
        log_entry = await process_log(db, log.model_dump(), source=agent_source(get_remote_address(request)))
    except EventNormalizationError as e:
        raise HTTPException(status_code=422, detail=f"Event could not be normalized: {e}")
    return log_entry


@logs_router.post("/ingest/batch")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def ingest_batch(request: Request, logs: List[LogCreate], db: Session = Depends(get_db), x_api_key: Optional[str] = Header(None)):
    """
    Ingest multiple log entries at once.
    Requires valid agent API key in X-API-Key header.
    """
    # Verify agent API key
    if not verify_agent_key(x_api_key or ""):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing agent API key. Include X-API-Key header."
        )

    # The whole batch is stored atomically: if any entry fails, none are stored,
    # so an agent retrying the batch does not create partial duplicates.
    try:
        entries = await process_logs(
            db, [log.model_dump() for log in logs], source=agent_source(get_remote_address(request))
        )
    except EventNormalizationError as e:
        raise HTTPException(status_code=422, detail=f"Event could not be normalized: {e}")
    results = [entry.id for entry in entries]
    return {"ingested": len(results), "log_ids": results}


@logs_router.get("/", response_model=List[LogOut])
def get_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None, max_length=50),
    anomaly_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve logs with optional filtering."""
    query = db.query(Log)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    if anomaly_only:
        query = query.filter(Log.anomaly == True)
    return query.order_by(desc(Log.timestamp)).offset(skip).limit(limit).all()


@events_router.get("/", response_model=List[SecurityEventOut])
def get_security_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None, max_length=50),
    source_type: Optional[str] = Query(None, max_length=50),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List normalized security events with optional time and type filters."""
    if since and until and since > until:
        raise HTTPException(status_code=422, detail="since must be earlier than or equal to until")
    query = db.query(SecurityEvent)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if source_type:
        query = query.filter(SecurityEvent.source_type == source_type)
    if since:
        query = query.filter(SecurityEvent.timestamp >= since)
    if until:
        query = query.filter(SecurityEvent.timestamp <= until)
    return query.order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id)).offset(skip).limit(limit).all()


@logs_router.get("/count")
def get_log_count(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Return total log count."""
    return {"count": db.query(Log).count()}


# ═══════════════════════════════════════════════════════════════
# ALERT ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@alerts_router.get("/", response_model=List[AlertOut])
def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve alerts with optional filtering."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    return query.order_by(desc(Alert.timestamp)).offset(skip).limit(limit).all()


@alerts_router.get("/count")
def get_alert_count(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Return active (unacknowledged) alert count."""
    active = db.query(Alert).filter(Alert.acknowledged == False).count()
    total = db.query(Alert).count()
    return {"active": active, "total": total}


@alerts_router.patch("/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(
    alert_id: int,
    body: AlertAcknowledge,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
):
    """Acknowledge or un-acknowledge an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.acknowledged = body.acknowledged
    db.commit()
    db.refresh(alert)

    # Audit log
    action = "acknowledged" if body.acknowledged else "unacknowledged"
    audit = AuditLog(
        user_id=current_user.id,
        action="alert_acknowledge",
        details=f"User {current_user.username} {action} alert {alert_id}: {alert.message}"
    )
    db.add(audit)
    db.commit()

    return alert


# ═══════════════════════════════════════════════════════════════
# NETWORK ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@network_router.post("/capture")
async def capture_network(
    count: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    caller: Optional[User] = Depends(require_agent_or_role("admin", "analyst")),
):
    """
    Trigger a network capture/simulation and store results.
    Callable by agents (X-API-Key) or admin/analyst users.
    """
    activities = network_analyzer.capture_packets(count)
    stored = []
    for act in activities:
        record = NetworkActivity(
            ip=act["ip"],
            packets=act["packets"],
            bytes_transferred=act.get("bytes_transferred", 0),
            protocol=act.get("protocol"),
            suspicious=act.get("suspicious", False),
        )
        db.add(record)
        stored.append(act)
    db.commit()
    return {"captured": len(stored), "activities": stored}


@network_router.get("/activity", response_model=List[NetworkActivityOut])
def get_network_activity(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    suspicious_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve stored network activity records."""
    query = db.query(NetworkActivity)
    if suspicious_only:
        query = query.filter(NetworkActivity.suspicious == True)
    return query.order_by(desc(NetworkActivity.timestamp)).offset(skip).limit(limit).all()


@network_router.get("/top-ips")
def get_top_ips(current_user: User = Depends(get_current_user)):
    """Return top IPs by packet count from the analyzer."""
    return network_analyzer.get_top_ips()


@network_router.get("/stats")
def get_network_stats(current_user: User = Depends(get_current_user)):
    """Return network capture statistics."""
    return network_analyzer.get_stats()


# ═══════════════════════════════════════════════════════════════
# DASHBOARD ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@dashboard_router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Aggregated stats for the dashboard overview."""
    total_logs = db.query(Log).count()
    active_alerts = db.query(Alert).filter(Alert.acknowledged == False).count()
    network_events = db.query(NetworkActivity).count()
    anomalies = db.query(Log).filter(Log.anomaly == True).count()
    return DashboardStats(
        total_logs=total_logs,
        active_alerts=active_alerts,
        network_events=network_events,
        anomalies_detected=anomalies,
        system_status="operational",
    )


@dashboard_router.get("/timeline", response_model=List[TimelineEvent])
def get_timeline(
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns a unified timeline of recent events:
    logs that triggered anomalies + their alerts.
    """
    # Recent anomalous logs
    anomalous_logs = (
        db.query(Log)
        .filter(Log.anomaly == True)
        .order_by(desc(Log.timestamp))
        .limit(limit)
        .all()
    )
    # Recent alerts
    recent_alerts = (
        db.query(Alert)
        .order_by(desc(Alert.timestamp))
        .limit(limit)
        .all()
    )
    timeline = []
    for log in anomalous_logs:
        timeline.append(TimelineEvent(
            id=log.id,
            event_type=log.event_type,
            message=f"Anomaly detected: {log.event_type} from {log.ip}",
            ip=log.ip,
            severity=None,
            timestamp=log.timestamp,
        ))
    for alert in recent_alerts:
        timeline.append(TimelineEvent(
            id=alert.id + 100000,  # offset to avoid ID collision
            event_type="alert",
            message=alert.message,
            ip=alert.ip,
            severity=alert.severity,
            timestamp=alert.timestamp,
        ))
    # Sort by timestamp descending  
    timeline.sort(key=lambda e: e.timestamp, reverse=True)
    return timeline[:limit]


@dashboard_router.get("/login-timeline")
def get_login_timeline(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Login attempt counts grouped by hour for chart display."""
    logs = (
        db.query(Log)
        .filter(Log.event_type == "login")
        .order_by(desc(Log.timestamp))
        .limit(500)
        .all()
    )
    hourly: Dict[str, int] = {}
    for log in logs:
        key = log.timestamp.strftime("%Y-%m-%d %H:00")
        hourly[key] = hourly.get(key, 0) + 1

    return [{"time": k, "count": v} for k, v in sorted(hourly.items())]


@dashboard_router.get("/alert-frequency")
def get_alert_frequency(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Alert counts grouped by hour for chart display."""
    alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(500).all()
    hourly: Dict[str, int] = {}
    for alert in alerts:
        key = alert.timestamp.strftime("%Y-%m-%d %H:00")
        hourly[key] = hourly.get(key, 0) + 1

    return [{"time": k, "count": v} for k, v in sorted(hourly.items())]


@dashboard_router.get("/top-suspicious-ips")
def get_top_suspicious_ips(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Top IPs involved in anomalous logs."""
    results = (
        db.query(Log.ip, func.count(Log.id).label("count"))
        .filter(Log.anomaly == True)
        .group_by(Log.ip)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    return [{"ip": r.ip, "count": r.count} for r in results]


# ═══════════════════════════════════════════════════════════════
# ATTACK SIMULATOR ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@simulator_router.post("/random")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def trigger_random_attack(request: Request, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin", "analyst"))):
    """
    Trigger a random attack simulation and ingest logs.
    Restricted to admin and analyst roles.
    """
    attack_logs = run_random_attack()
    ingested = []
    for log_data in attack_logs:
        entry = await process_log(db, log_data, source=simulator_source())
        ingested.append(entry.id)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="simulate_attack",
        details=f"User {current_user.username} triggered random attack simulation"
    )
    db.add(audit)
    db.commit()

    return {"attack": "random", "logs_ingested": len(ingested)}


@simulator_router.post("/all")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def trigger_all_attacks(request: Request, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin", "analyst"))):
    """
    Run all attack simulations at once.
    Restricted to admin and analyst roles.
    """
    attack_logs = run_all_attacks()
    ingested = []
    for log_data in attack_logs:
        entry = await process_log(db, log_data, source=simulator_source())
        ingested.append(entry.id)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="simulate_attack",
        details=f"User {current_user.username} triggered all attack simulations"
    )
    db.add(audit)
    db.commit()

    return {"attack": "all", "logs_ingested": len(ingested)}


# ── Database Guardian Router ────────────────────────────────
from secret_provider import get_secret_provider
from database_guardian.risk_scorer import calculate_database_risk_score
from database_guardian.db_connector import create_connector

@database_router.post("/", response_model=DatabaseAssetOut)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
def register_database(
    request: Request,
    database: DatabaseAssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))
):
    """Register a new database for monitoring."""
    if database.db_type == "postgresql" and (not database.host or not database.port):
        raise HTTPException(status_code=422, detail="PostgreSQL registrations require a host and port")
    if db.query(DatabaseAsset).filter(DatabaseAsset.name == database.name).first():
        raise HTTPException(status_code=409, detail="A database with this name is already registered")
    # Encrypt password
    encrypted_pwd = get_secret_provider().encrypt(database.password)

    # Create asset
    db_asset = DatabaseAsset(
        name=database.name,
        db_type=database.db_type,
        host=database.host,
        port=database.port,
        database_name=database.database_name,
        username=database.username,
        encrypted_password=encrypted_pwd
    )
    db.add(db_asset)
    db.add(AuditLog(
        user_id=current_user.id,
        action="database_registered",
        details=f"Database {database.name} registered for monitoring"
    ))
    db.commit()
    db.refresh(db_asset)

    return db_asset

@database_router.get("/", response_model=List[DatabaseAssetOut])
def list_databases(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all registered databases."""
    return db.query(DatabaseAsset).all()

@database_router.get("/{database_id}", response_model=DatabaseAssetOut)
def get_database(
    database_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get database details."""
    db_asset = db.query(DatabaseAsset).filter(DatabaseAsset.id == database_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Database not found")
    return db_asset

@database_router.patch("/{database_id}", response_model=DatabaseAssetOut)
def update_database(
    database_id: int,
    update: DatabaseAssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update the display name or monitoring state of a registered database."""
    db_asset = db.query(DatabaseAsset).filter(DatabaseAsset.id == database_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Database not found")
    changes = update.model_dump(exclude_unset=True)
    changes.pop("maintenance_windows", None)
    windows = update.maintenance_windows or []
    maintenance_changed = "maintenance_windows" in update.model_fields_set
    for field, value in changes.items():
        setattr(db_asset, field, value)
    if maintenance_changed:
        try:
            metadata = json.loads(db_asset.metadata_json or "{}")
        except ValueError:
            metadata = {}
        metadata["maintenance_windows"] = [
            {"start": w.start.isoformat(), "end": w.end.isoformat(),
             "categories": list(w.categories), "multiplier": w.multiplier}
            for w in windows
        ]
        db_asset.metadata_json = json.dumps(metadata)
        changes["maintenance_windows"] = True
    if changes:
        db.add(AuditLog(
            user_id=current_user.id,
            action="database_updated",
            details=f"Database {db_asset.name} updated ({', '.join(sorted(changes))})",
        ))
        db.commit()
        db.refresh(db_asset)
    return db_asset

@database_router.post("/{database_id}/test-connection")
def test_database_connection(
    database_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
):
    """Try the stored connection and return safe status details."""
    db_asset = db.query(DatabaseAsset).filter(DatabaseAsset.id == database_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Database not found")
    connector = None
    try:
        connector = create_connector(db_asset)
        connector.connect()
        version = connector.get_database_version()
        db_asset.status = "online"
        db_asset.last_check = datetime.now(timezone.utc)
        db.commit()
        return {"status": "connected", "database_id": database_id, "version": version}
    except Exception:
        db.rollback()
        db_asset.status = "offline"
        db_asset.last_check = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=502, detail="Could not connect to the registered database") from None
    finally:
        if connector is not None:
            try:
                connector.close()
            except Exception:
                pass

@database_router.get("/{database_id}/alerts", response_model=List[DatabaseAlertOut])
def get_database_alerts(
    database_id: int,
    skip: int = 0,
    limit: int = 50,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get alerts for a specific database."""
    query = db.query(DatabaseAlert).filter(DatabaseAlert.database_id == database_id)
    if acknowledged is not None:
        query = query.filter(DatabaseAlert.acknowledged == acknowledged)
    return query.order_by(desc(DatabaseAlert.timestamp)).offset(skip).limit(limit).all()

@database_router.get("/{database_id}/risk-score", response_model=DatabaseRiskScoreBreakdown)
def get_database_risk_score(
    database_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed risk score breakdown for a database."""
    db_asset = db.query(DatabaseAsset).filter(DatabaseAsset.id == database_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Database not found")

    risk_breakdown = calculate_database_risk_score(db, database_id)
    category_scores = {key: value for key, value in risk_breakdown.items() if key != "total_risk_score"}

    return DatabaseRiskScoreBreakdown(
        database_id=database_id,
        database_name=db_asset.name,
        total_risk_score=risk_breakdown["total_risk_score"],
        **category_scores
    )


@database_router.get("/{database_id}/risk-history", response_model=List[DatabaseRiskSnapshotOut])
def get_database_risk_history(
    database_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stored risk snapshots (score, severity, reasons, event references), newest first."""
    if not db.query(DatabaseAsset.id).filter(DatabaseAsset.id == database_id).first():
        raise HTTPException(status_code=404, detail="Database not found")
    snapshots = (
        db.query(DatabaseRiskSnapshot)
        .filter(DatabaseRiskSnapshot.database_id == database_id)
        .order_by(desc(DatabaseRiskSnapshot.id))
        .offset(skip).limit(limit).all()
    )
    return [
        DatabaseRiskSnapshotOut(
            id=snap.id, database_id=snap.database_id, calculated_at=snap.calculated_at,
            total_score=snap.total_score, severity=snap.severity,
            contributions=json.loads(snap.contributions_json), scoring_version=snap.scoring_version)
        for snap in snapshots
    ]

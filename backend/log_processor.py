"""
AI-SIEM Guardian — Log Processor
Ingests logs, enriches metadata, runs AI detection, normalizes them into
SecurityEvents, and stores results.

Transaction model: all Logs and their SecurityEvents from one call (a single
log or a whole batch) are written in ONE transaction. If enrichment,
normalization or persistence fails for any item, everything is rolled back and
nothing from that call is stored. Side effects (WebSocket broadcast, alerts,
retraining) run only after a successful commit.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from models import Log
from ai_engine import anomaly_detector
from alert_service import create_alert, determine_severity, generate_alert_message
from event_normalizer import EventNormalizationError, IngestionSource, agent_source, normalize_agent_log
from websocket_manager import ws_manager

logger = logging.getLogger(__name__)

RETRAIN_EVERY = 50


async def process_log(db: Session, log_data: Dict, source: Optional[IngestionSource] = None) -> Log:
    """Process a single log (see process_logs). Returns the stored Log."""
    return (await process_logs(db, [log_data], source=source))[0]


async def process_logs(db: Session, items: List[Dict], source: Optional[IngestionSource] = None) -> List[Log]:
    """
    Full ingestion pipeline for one or more logs:
      1. Enrich each log with computed metadata
      2. Run anomaly detection
      3. Store the Log and its normalized SecurityEvent   (single transaction)
      4. After commit: broadcast via WebSocket, create alerts for anomalies,
         periodic retraining
    Raises EventNormalizationError for malformed input; nothing is stored then.
    """
    source = source or agent_source(None)
    if not items:
        return []

    logs_before = db.query(Log).count()
    stored: List[Tuple[Log, bool, Dict]] = []
    try:
        for index, log_data in enumerate(items):
            log_entry, is_anomaly = _build_log(db, log_data)
            db.add(log_entry)
            db.flush()  # assign id; later items' enrichment queries see this row (as before)
            try:
                event = normalize_agent_log(log_entry, source, ingested_at=log_entry.timestamp)
            except EventNormalizationError as e:
                raise EventNormalizationError(f"item {index}: {e}") from None
            db.add(event)
            db.flush()  # surface constraint errors before commit
            stored.append((log_entry, is_anomaly, log_data))
        db.commit()
    except Exception:
        db.rollback()
        raise

    for log_entry, is_anomaly, log_data in stored:
        db.refresh(log_entry)
        await _after_commit(db, log_entry, is_anomaly, log_data)

    # Periodic retraining: same trigger as before (total log count reaching a
    # multiple of RETRAIN_EVERY), evaluated across the whole committed call.
    logs_after = logs_before + len(stored)
    crossed = logs_after // RETRAIN_EVERY > logs_before // RETRAIN_EVERY
    if crossed and logs_after >= 20:
        _retrain_model(db)

    return [entry for entry, _, _ in stored]


def _build_log(db: Session, log_data: Dict) -> Tuple[Log, bool]:
    """Enrich `log_data` in place, run detection, and build (not persist) the Log."""
    now = datetime.now(timezone.utc)
    log_data["hour_of_day"] = now.hour

    # Compute login_frequency: count recent logs from this user
    if log_data.get("user"):
        recent_count = (
            db.query(Log)
            .filter(Log.user == log_data["user"])
            .limit(100)
            .count()
        )
        log_data.setdefault("login_frequency", min(recent_count, 100))

    # Compute ip_activity_rate: count recent logs from this IP
    ip_count = (
        db.query(Log)
        .filter(Log.ip == log_data["ip"])
        .limit(200)
        .count()
    )
    log_data.setdefault("ip_activity_rate", min(ip_count, 200))

    is_anomaly = anomaly_detector.predict(log_data)

    log_entry = Log(
        user=log_data.get("user"),
        ip=log_data["ip"],
        event_type=log_data.get("event_type", "unknown"),
        failed_attempts=log_data.get("failed_attempts", 0),
        login_frequency=log_data.get("login_frequency", 0),
        ip_activity_rate=log_data.get("ip_activity_rate", 0),
        anomaly=is_anomaly,
        raw_data=json.dumps(log_data),
        timestamp=now,
    )
    return log_entry, is_anomaly


async def _after_commit(db: Session, log_entry: Log, is_anomaly: bool, log_data: Dict):
    # ── Broadcast log via WebSocket ──────────────────────────────
    log_broadcast = {
        "id": log_entry.id,
        "user": log_entry.user,
        "ip": log_entry.ip,
        "event_type": log_entry.event_type,
        "failed_attempts": log_entry.failed_attempts,
        "anomaly": log_entry.anomaly,
        "timestamp": log_entry.timestamp.isoformat(),
    }
    await ws_manager.broadcast_log(log_broadcast)

    # ── Create alert if anomaly ──────────────────────────────────
    if is_anomaly:
        severity = determine_severity(log_data)
        # Infer alert type from patterns
        alert_type = _infer_alert_type(log_data)
        message = generate_alert_message(log_data, alert_type)
        await create_alert(
            db=db,
            message=message,
            ip=log_data.get("ip"),
            severity=severity,
            alert_type=alert_type,
            log_id=log_entry.id,
        )


def _infer_alert_type(log_data: Dict) -> str:
    """Infer the type of attack from log characteristics."""
    failed = log_data.get("failed_attempts", 0)
    freq = log_data.get("login_frequency", 0)
    ip_rate = log_data.get("ip_activity_rate", 0)
    event = log_data.get("event_type", "")

    if failed >= 5:
        return "brute_force"
    if freq > 30:
        return "high_frequency"
    if ip_rate > 80:
        return "credential_stuffing"
    if event == "port_scan":
        return "port_scan"
    if event == "geo_anomaly":
        return "geo_anomaly"
    return "anomaly"


def _retrain_model(db: Session):
    """Retrain the AI model on all stored logs."""
    logs = db.query(Log).order_by(Log.timestamp.desc()).limit(500).all()
    training_data = [
        {
            "failed_attempts": log.failed_attempts,
            "login_frequency": log.login_frequency,
            "ip_activity_rate": log.ip_activity_rate,
            "hour_of_day": log.timestamp.hour if log.timestamp else 12,
        }
        for log in logs
    ]
    anomaly_detector.train(training_data)

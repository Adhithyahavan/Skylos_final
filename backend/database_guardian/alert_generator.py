"""
Alert Generator - Create database-specific alerts with risk score impacts.
"""
import json
from sqlalchemy.orm import Session
from models import DatabaseAlert
from datetime import datetime, timedelta, timezone
from .risk_scorer import alert_risk_impact

# An unacknowledged alert with the same identity inside this window is not repeated.
ALERT_DEDUP_WINDOW = timedelta(minutes=30)

async def create_database_alert(
    db: Session,
    database_id: int,
    alert_type: str,
    severity: str,
    title: str,
    description: str,
    username: str = None,
    source_ip: str = None,
    affected_table: str = None,
    evidence: dict = None
):
    """Create and broadcast a database alert."""

    now = datetime.now(timezone.utc)
    existing = (
        db.query(DatabaseAlert)
        .filter(
            DatabaseAlert.database_id == database_id,
            DatabaseAlert.alert_type == alert_type,
            DatabaseAlert.severity == severity,
            DatabaseAlert.username == username,
            DatabaseAlert.source_ip == source_ip,
            DatabaseAlert.affected_table == affected_table,
            DatabaseAlert.acknowledged == False,  # noqa: E712
            DatabaseAlert.timestamp >= now - ALERT_DEDUP_WINDOW,
        )
        .order_by(DatabaseAlert.id.desc())
        .first()
    )
    if existing:
        return existing

    # Specification weight for this alert type (0 when the type carries none)
    risk_impact = alert_risk_impact(alert_type, evidence)

    alert = DatabaseAlert(
        database_id=database_id,
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=description,
        username=username,
        source_ip=source_ip,
        affected_table=affected_table,
        evidence_json=json.dumps(evidence) if evidence else None,
        risk_score_impact=risk_impact,
        timestamp=now
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Broadcast via WebSocket - import here to avoid circular imports
    try:
        from websocket_manager import ws_manager
        alert_data = {
            "id": alert.id,
            "database_id": database_id,
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "timestamp": alert.timestamp.isoformat()
        }
        await ws_manager.broadcast_alert(alert_data)
    except ImportError:
        # Websocket manager not available yet, skip broadcast
        pass

    return alert
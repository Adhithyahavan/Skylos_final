"""
Alert Generator - Create database-specific alerts with risk score impacts.
"""
import json
from sqlalchemy.orm import Session
from models import DatabaseAlert
from datetime import datetime, timezone
from .risk_scorer import RISK_WEIGHTS

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

    # Determine risk score impact
    risk_impact = RISK_WEIGHTS.get(alert_type.replace("db_", ""), 5)

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
        timestamp=datetime.now(timezone.utc)
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
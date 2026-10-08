"""
Risk Scorer - Calculate database risk scores based on suspicious events.
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabaseAlert, DatabaseLoginEvent

# Risk score weights (from user requirements)
RISK_WEIGHTS = {
    "failed_logins_3_4": 5,
    "failed_logins_5_9": 15,
    "failed_logins_10_plus": 25,
    "new_admin": 25,
    "privilege_escalation": 30,
    "audit_disabled": 40,
    "missing_backup": 20,
    "failed_backup": 25,
    "schema_change": 5,
    "sensitive_access": 15,
    "large_export": 30,
    "out_of_hours": 5,
    "unknown_ip": 10,
    "multiple_events": 15,
}

def calculate_database_risk_score(db: Session, database_id: int) -> dict:
    """
    Calculate comprehensive risk score for a database.
    Returns dict with total score and breakdown by category.
    """
    score_breakdown = {
        "failed_logins_score": 0,
        "privilege_changes_score": 0,
        "schema_changes_score": 0,
        "audit_disabled_score": 0,
        "backup_issues_score": 0,
        "sensitive_access_score": 0,
        "other_score": 0,
    }

    # Time window for analysis (last 24 hours)
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    # 1. Failed login attempts
    failed_logins = (
        db.query(DatabaseLoginEvent)
        .filter(
            DatabaseLoginEvent.database_id == database_id,
            DatabaseLoginEvent.success == False,
            DatabaseLoginEvent.timestamp >= since
        )
        .count()
    )

    if failed_logins >= 10:
        score_breakdown["failed_logins_score"] = RISK_WEIGHTS["failed_logins_10_plus"]
    elif failed_logins >= 5:
        score_breakdown["failed_logins_score"] = RISK_WEIGHTS["failed_logins_5_9"]
    elif failed_logins >= 3:
        score_breakdown["failed_logins_score"] = RISK_WEIGHTS["failed_logins_3_4"]

    # 2. Recent unacknowledged alerts
    recent_alerts = (
        db.query(DatabaseAlert)
        .filter(
            DatabaseAlert.database_id == database_id,
            DatabaseAlert.acknowledged == False,
            DatabaseAlert.timestamp >= since
        )
        .all()
    )

    for alert in recent_alerts:
        # Add alert's risk score impact to appropriate category
        if "privilege" in alert.alert_type or "admin" in alert.alert_type:
            score_breakdown["privilege_changes_score"] += alert.risk_score_impact
        elif "schema" in alert.alert_type:
            score_breakdown["schema_changes_score"] += alert.risk_score_impact
        elif "audit" in alert.alert_type:
            score_breakdown["audit_disabled_score"] += alert.risk_score_impact
        elif "backup" in alert.alert_type:
            score_breakdown["backup_issues_score"] += alert.risk_score_impact
        elif "sensitive" in alert.alert_type or "export" in alert.alert_type:
            score_breakdown["sensitive_access_score"] += alert.risk_score_impact
        else:
            score_breakdown["other_score"] += alert.risk_score_impact

    # Calculate total (cap at 100)
    total_score = min(100, sum(score_breakdown.values()))

    return {
        "total_risk_score": total_score,
        **score_breakdown
    }
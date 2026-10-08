"""
AI-SIEM Guardian — Alert Service
Creates, stores, and dispatches alerts via WebSocket + email.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from models import Alert, Log
from websocket_manager import ws_manager

logger = logging.getLogger(__name__)


async def create_alert(
    db: Session,
    message: str,
    ip: Optional[str] = None,
    severity: str = "medium",
    alert_type: str = "anomaly",
    log_id: Optional[int] = None,
) -> Alert:
    """
    Persist an alert in the database, then broadcast it via WebSocket
    and optionally send an email notification.
    """
    alert = Alert(
        log_id=log_id,
        severity=severity,
        message=message,
        ip=ip,
        alert_type=alert_type,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # ── Broadcast via WebSocket ──────────────────────────────────
    alert_data = {
        "id": alert.id,
        "severity": alert.severity,
        "message": alert.message,
        "ip": alert.ip,
        "alert_type": alert.alert_type,
        "timestamp": alert.timestamp.isoformat(),
    }
    await ws_manager.broadcast_alert(alert_data)

    # ── Email notification (best-effort) ─────────────────────────
    try:
        await send_email_alert(alert)
    except Exception as e:
        logger.warning(f"Email alert failed: {e}")

    logger.info(f"Alert created: [{severity}] {message}")
    return alert


def determine_severity(log_entry) -> str:
    """Determine alert severity based on log attributes."""
    failed = getattr(log_entry, "failed_attempts", 0) if hasattr(log_entry, "failed_attempts") else log_entry.get("failed_attempts", 0)
    ip_rate = getattr(log_entry, "ip_activity_rate", 0) if hasattr(log_entry, "ip_activity_rate") else log_entry.get("ip_activity_rate", 0)

    if failed >= 10 or ip_rate >= 100:
        return "critical"
    if failed >= 5 or ip_rate >= 50:
        return "high"
    if failed >= 3 or ip_rate >= 20:
        return "medium"
    return "low"


def generate_alert_message(log_entry, alert_type: str = "anomaly") -> str:
    """Generate a human-readable alert message from a log entry."""
    ip = getattr(log_entry, "ip", None) or log_entry.get("ip", "unknown")
    user = getattr(log_entry, "user", None) or log_entry.get("user", "unknown")
    failed = getattr(log_entry, "failed_attempts", 0) if hasattr(log_entry, "failed_attempts") else log_entry.get("failed_attempts", 0)

    templates = {
        "brute_force": f"Brute-force attack detected from IP {ip} — {failed} failed attempts",
        "anomaly": f"Anomalous activity detected from IP {ip} (user: {user})",
        "port_scan": f"Port scanning detected from IP {ip}",
        "credential_stuffing": f"Credential stuffing attempt from IP {ip}",
        "geo_anomaly": f"Suspicious location change for user {user} from IP {ip}",
        "high_frequency": f"High-frequency login attempts from IP {ip}",
    }
    return templates.get(alert_type, f"Security alert: suspicious activity from IP {ip}")


async def send_email_alert(alert: Alert):
    """Send an email notification for the given alert (best-effort)."""
    from config import settings

    if not settings.SMTP_USERNAME or not settings.ALERT_EMAIL_TO:
        logger.debug("Email alerts not configured — skipping")
        return

    try:
        import aiosmtplib
        from email.mime.text import MIMEText

        msg = MIMEText(
            f"Security Alert Detected\n\n"
            f"Severity: {alert.severity.upper()}\n"
            f"Message: {alert.message}\n"
            f"IP: {alert.ip or 'N/A'}\n"
            f"Time: {alert.timestamp.isoformat()}\n\n"
            f"— AI-SIEM Guardian"
        )
        msg["Subject"] = f"[SIEM Guardian] {alert.severity.upper()} — {alert.alert_type}"
        msg["From"] = settings.SMTP_USERNAME
        msg["To"] = settings.ALERT_EMAIL_TO

        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_SERVER,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME,
            password=settings.SMTP_PASSWORD,
            start_tls=True,
        )
        logger.info(f"Email alert sent to {settings.ALERT_EMAIL_TO}")
    except Exception as e:
        logger.warning(f"Failed to send email: {e}")

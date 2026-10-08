"""
Login Monitor - Track database logins and detect brute force attacks.
"""
import asyncio
import logging
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabaseLoginEvent, DatabaseAlert
from .db_connector import create_connector
from datetime import datetime, timezone, timedelta
from .alert_generator import create_database_alert
import json

logger = logging.getLogger(__name__)

async def run_login_monitoring(db: Session):
    """Monitor database login attempts for brute force attacks."""
    assets = db.query(DatabaseAsset).filter(DatabaseAsset.is_active == True).all()

    for asset in assets:
        try:
            connector = create_connector(asset)
            conn = connector.connect()

            # Query recent connections (this is database-specific)
            # For now, we'll simulate by checking if we can connect
            # In a real implementation, this would query database logs
            # For demonstration, we'll create a sample login event

            # Simulate checking current connections (PostgreSQL example)
            if asset.db_type == "postgresql":
                try:
                    # Get current connections
                    result = connector.execute_query("""
                        SELECT usename, client_addr, backend_start
                        FROM pg_stat_activity
                        WHERE state = 'active'
                    """)

                    for row in result:
                        username, client_addr, backend_start = row
                        if username and client_addr:
                            # Check if this is a new connection we haven't seen recently
                            # For simplicity, we'll record all active connections as login events
                            # In production, you'd want to track new connections since last check

                            login_event = DatabaseLoginEvent(
                                database_id=asset.id,
                                username=str(username) if username else "unknown",
                                source_ip=str(client_addr) if client_addr else "0.0.0.0",
                                success=True,
                                timestamp=backend_start if backend_start else datetime.now(timezone.utc),
                                auth_method="password"  # Simplified
                            )
                            db.add(login_event)

                except Exception as e:
                    logger.debug(f"Could not query pg_stat_activity for {asset.name}: {e}")

            connector.close()

            # Check for brute force attacks (failed login attempts in last 60 seconds)
            one_minute_ago = datetime.now(timezone.utc) - timedelta(seconds=60)
            recent_failed_logins = db.query(DatabaseLoginEvent).filter(
                DatabaseLoginEvent.database_id == asset.id,
                DatabaseLoginEvent.success == False,
                DatabaseLoginEvent.timestamp >= one_minute_ago
            ).count()

            # Generate alerts based on failed login counts
            if recent_failed_logins >= 10:
                await create_database_alert(
                    db=db,
                    database_id=asset.id,
                    alert_type="db_brute_force",
                    severity="critical",
                    title=f"Brute Force Attack Detected on {asset.name}",
                    description=f"{recent_failed_logins} failed login attempts in the last minute",
                    evidence={"failed_logins_count": recent_failed_logins, "time_window": "60 seconds"}
                )
                logger.warning(f"Brute force alert triggered for {asset.name}: {recent_failed_logins} failed logins")
            elif recent_failed_logins >= 5:
                await create_database_alert(
                    db=db,
                    database_id=asset.id,
                    alert_type="db_brute_force",
                    severity="high",
                    title=f"Multiple Failed Logins on {asset.name}",
                    description=f"{recent_failed_logins} failed login attempts in the last minute",
                    evidence={"failed_logins_count": recent_failed_logins, "time_window": "60 seconds"}
                )
                logger.info(f"High severity failed login alert for {asset.name}: {recent_failed_logins} failed logins")
            elif recent_failed_logins >= 3:
                await create_database_alert(
                    db=db,
                    database_id=asset.id,
                    alert_type="db_brute_force",
                    severity="medium",
                    title=f"Failed Login Attempts on {asset.name}",
                    description=f"{recent_failed_logins} failed login attempts in the last minute",
                    evidence={"failed_logins_count": recent_failed_logins, "time_window": "60 seconds"}
                )
                logger.info(f"Medium severity failed login alert for {asset.name}: {recent_failed_logins} failed logins")

        except Exception as e:
            logger.error(f"Login monitoring error for {asset.name}: {e}")
        finally:
            db.commit()
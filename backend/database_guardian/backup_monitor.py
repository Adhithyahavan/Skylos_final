"""
Backup Monitor - Track database backup status and detect issues.
"""
import asyncio
import logging
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabaseBackup
from .db_connector import create_connector
from datetime import datetime, timezone, timedelta
from .alert_generator import create_database_alert
import json

logger = logging.getLogger(__name__)

async def run_backup_monitoring(db: Session):
    """Monitor database backup status for issues."""
    assets = db.query(DatabaseAsset).filter(DatabaseAsset.is_active == True).all()

    for asset in assets:
        try:
            connector = create_connector(asset)
            conn = connector.connect()

            # Check backup status (database-specific)
            if asset.db_type == "postgresql":
                try:
                    # Check for backup files or use pg_backup functions if available
                    # This is simplified - in production you'd integrate with your backup solution
                    # For demonstration, we'll check if there's a backup directory or use a simple check

                    # Get last backup time from our records
                    last_backup = db.query(DatabaseBackup).filter(
                        DatabaseBackup.database_id == asset.id
                    ).order_by(DatabaseBackup.backup_time.desc()).first()

                    # If no backup in last 24 hours, create warning
                    if not last_backup or last_backup.backup_time < datetime.now(timezone.utc) - timedelta(hours=24):
                        await create_database_alert(
                            db=db,
                            database_id=asset.id,
                            alert_type="db_missing_backup",
                            severity="high",
                            title=f"No Recent Backup for {asset.name}",
                            description=f"Database {asset.name} has not been backed up in the last 24 hours",
                            evidence={
                                "last_backup_time": last_backup.backup_time.isoformat() if last_backup else None,
                                "hours_since_backup": (
                                    (datetime.now(timezone.utc) - last_backup.backup_time).total_seconds() / 3600
                                    if last_backup else None
                                )
                            }
                        )

                    # Check for failed backups
                    failed_backups = db.query(DatabaseBackup).filter(
                        DatabaseBackup.database_id == asset.id,
                        DatabaseBackup.success == False,
                        DatabaseBackup.backup_time >= datetime.now(timezone.utc) - timedelta(hours=24)
                    ).count()

                    if failed_backups > 0:
                        await create_database_alert(
                            db=db,
                            database_id=asset.id,
                            alert_type="db_failed_backup",
                            severity="critical",
                            title=f"Failed Backups Detected for {asset.name}",
                            description=f"{failed_backups} backup(s) failed in the last 24 hours",
                            evidence={"failed_backups_count": failed_backups, "time_window": "24 hours"}
                        )

                except Exception as e:
                    logger.debug(f"Could not check backup status for {asset.name}: {e}")

            connector.close()

            # Record that we performed a backup check
            backup_record = DatabaseBackup(
                database_id=asset.id,
                backup_time=datetime.now(timezone.utc),
                backup_type="monitoring_check",
                backup_size_mb=0,
                success=True,  # Monitoring check itself succeeded
                verification_status="not_verified"
            )
            db.add(backup_record)

        except Exception as e:
            logger.error(f"Backup monitoring error for {asset.name}: {e}")
        finally:
            db.commit()
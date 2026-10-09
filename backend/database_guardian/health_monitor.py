"""
Health Monitor - Perform database health checks every 5 minutes.
"""
import asyncio
import logging
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabaseHealthCheck
from .db_connector import create_connector
from datetime import datetime, timezone
import time

logger = logging.getLogger(__name__)

async def run_health_checks(db: Session):
    """Run health checks for all active database assets."""
    assets = db.query(DatabaseAsset).filter(DatabaseAsset.is_active == True).all()

    for asset in assets:
        start_time = time.time()
        try:
            connector = create_connector(asset)
            conn = connector.connect()

            # Get database version and size
            version = connector.get_database_version()
            size_mb = connector.get_database_size_mb()

            # Get connection count (PostgreSQL specific)
            connection_count = None
            if asset.db_type == "postgresql":
                try:
                    result = connector.execute_query(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                    )
                    connection_count = result[0][0] if result else None
                except Exception:
                    pass  # Ignore errors in getting connection count

            connector.close()

            response_time_ms = int((time.time() - start_time) * 1000)

            # Record health check
            health_check = DatabaseHealthCheck(
                database_id=asset.id,
                status="online",
                response_time_ms=response_time_ms,
                connection_count=connection_count,
                database_size_mb=size_mb
            )
            db.add(health_check)

            # Update asset status and last check
            asset.status = "online"
            asset.last_check = datetime.now(timezone.utc)
            asset.risk_score = calculate_risk_score(db, asset.id)

            logger.info(f"Health check for {asset.name}: online ({response_time_ms}ms)")

        except Exception as e:
            logger.error(f"Health check failed for {asset.name}: {e}")

            # Record failed health check
            health_check = DatabaseHealthCheck(
                database_id=asset.id,
                status="offline",
                error_message=str(e)[:500]  # Limit error message length
            )
            db.add(health_check)

            # Update asset status
            asset.status = "offline"
            asset.last_check = datetime.now(timezone.utc)

        finally:
            db.commit()

def calculate_risk_score(db: Session, database_id: int) -> int:
    """Score a database and store the explained snapshot when it changed."""
    from .risk_scorer import evaluate_database_risk, record_risk_snapshot
    result = evaluate_database_risk(db, database_id)
    record_risk_snapshot(db, database_id, result)
    return result.total

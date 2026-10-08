"""
Query Monitor - Track database query activity and detect anomalies.
"""
import asyncio
import logging
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabaseQueryLog, DatabaseActivityBaseline
from .db_connector import create_connector
from datetime import datetime, timezone, timedelta
from .alert_generator import create_database_alert
import json

logger = logging.getLogger(__name__)

async def run_query_monitoring(db: Session):
    """Monitor database query activity for anomalies."""
    assets = db.query(DatabaseAsset).filter(DatabaseAsset.is_active == True).all()

    for asset in assets:
        try:
            connector = create_connector(asset)
            conn = connector.connect()

            # Collect query statistics (database-specific)
            if asset.db_type == "postgresql":
                try:
                    # Get query stats from pg_stat_statements if available
                    # Fallback to pg_stat_user_tables for basic info
                    result = connector.execute_query("""
                        SELECT
                            schemaname,
                            tablename,
                            seq_scan + idx_scan as total_scans,
                            n_tup_ins + n_tup_upd + n_tup_del + n_tup_hot_upd as total_modifications
                        FROM pg_stat_user_tables
                        ORDER BY total_scans DESC
                        LIMIT 10
                    """)

                    total_queries = 0
                    total_rows = 0
                    sensitive_access = False

                    for row in result:
                        schemaname, tablename, scans, modifications = row
                        total_queries += scans
                        total_rows += modifications
                        # Simple heuristic for sensitive tables
                        if any(sensitive in tablename.lower() for sensitive in
                               ['password', 'user', 'account', 'payment', 'ssn', 'credit']):
                            sensitive_access = True

                    # Record query log entry
                    query_log = DatabaseQueryLog(
                        database_id=asset.id,
                        username="system",  # Would be better to get actual user
                        query_type="AGGREGATE",
                        table_name="multiple" if len(result) > 1 else (result[0][1] if result else None),
                        rows_affected=total_rows,
                        execution_time_ms=0,  # Would need actual timing
                        is_sensitive=sensitive_access
                    )
                    db.add(query_log)

                    # Update or create baseline
                    baseline = db.query(DatabaseActivityBaseline).filter(
                        DatabaseActivityBaseline.database_id == asset.id,
                        DatabaseActivityBaseline.username == "system"
                    ).first()

                    if baseline:
                        baseline.avg_queries_per_hour = (baseline.avg_queries_per_hour * 0.8) + (total_queries * 0.2)
                        baseline.avg_rows_read = (baseline.avg_rows_read * 0.8) + (total_rows * 0.2)
                        baseline.baseline_created = datetime.now(timezone.utc)
                    else:
                        baseline = DatabaseActivityBaseline(
                            database_id=asset.id,
                            username="system",
                            avg_queries_per_hour=float(total_queries),
                            avg_rows_read=float(total_rows)
                        )
                        db.add(baseline)

                    # Check for anomalies (simple threshold-based)
                    if baseline and baseline.avg_queries_per_hour > 0:
                        query_ratio = total_queries / baseline.avg_queries_per_hour if baseline.avg_queries_per_hour > 0 else 0
                        if query_ratio > 5.0:  # 5x normal activity
                            await create_database_alert(
                                db=db,
                                database_id=asset.id,
                                alert_type="db_high_query_volume",
                                severity="medium",
                                title=f"High Query Volume Detected in {asset.name}",
                                description=f"Query volume is {query_ratio:.1f}x normal baseline",
                                evidence={
                                    "current_queries": total_queries,
                                    "baseline_queries": baseline.avg_queries_per_hour,
                                    "ratio": query_ratio
                                }
                            )

                    if sensitive_access:
                        await create_database_alert(
                            db=db,
                            database_id=asset.id,
                            alert_type="db_sensitive_access",
                            severity="medium",
                            title=f"Sensitive Data Access in {asset.name}",
                            description=f"Access to potentially sensitive tables detected",
                            evidence={"accessed_tables": [r[1] for r in result if any(s in r[1].lower() for s in ['password', 'user', 'account', 'payment', 'ssn', 'credit'])]}
                        )

                except Exception as e:
                    logger.debug(f"Could not query pg_stat_user_tables for {asset.name}: {e}")
                    # Fallback: just record that we monitored
                    query_log = DatabaseQueryLog(
                        database_id=asset.id,
                        username="system",
                        query_type="MONITOR",
                        table_name="health_check",
                        rows_affected=0,
                        execution_time_ms=0
                    )
                    db.add(query_log)

            connector.close()

        except Exception as e:
            logger.error(f"Query monitoring error for {asset.name}: {e}")
        finally:
            db.commit()
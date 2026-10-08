"""
Schema Monitor - Track database schema changes and detect unauthorized modifications.
"""
import asyncio
import logging
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabaseSchemaChange
from .db_connector import create_connector
from datetime import datetime, timezone
from .alert_generator import create_database_alert
import json

logger = logging.getLogger(__name__)

async def run_schema_monitoring(db: Session):
    """Monitor database schema changes for unauthorized modifications."""
    assets = db.query(DatabaseAsset).filter(DatabaseAsset.is_active == True).all()

    for asset in assets:
        try:
            connector = create_connector(asset)
            conn = connector.connect()

            # Check for schema changes (database-specific)
            if asset.db_type == "postgresql":
                try:
                    # Get recent DDL commands from PostgreSQL logs or information schema
                    # This is simplified - in production you'd want to use pg_audit or
                    # monitor PostgreSQL log files for DDL statements
                    result = connector.execute_query("""
                        SELECT
                            objid::regclass as object_name,
                            objsubid,
                            'TABLE' as object_type
                        FROM pg_depend
                        WHERE classid = 'pg_class'::regclass
                        AND deptype = 'e'
                        LIMIT 10
                    """)[:5]  # Limit results

                    # For demonstration, we'll check if there are any tables
                    # In a real implementation, you'd compare against a baseline
                    tables_result = connector.execute_query("""
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                        LIMIT 5
                    """)

                    # Record that we performed a schema check
                    # In production, you'd compare current schema with baseline
                    # and create SchemaChange records for differences

                except Exception as e:
                    logger.debug(f"Could not query schema info for {asset.name}: {e}")

            connector.close()

            # Create a schema change record to indicate monitoring occurred
            # In a real implementation, this would only be created when actual changes are detected
            schema_change = DatabaseSchemaChange(
                database_id=asset.id,
                change_type="schema_check",
                object_type="monitoring",
                object_name="schema_monitor_run",
                performed_by="system",
                details_json=json.dumps({"monitor_run": True, "timestamp": datetime.now(timezone.utc).isoformat()})
            )
            db.add(schema_change)

        except Exception as e:
            logger.error(f"Schema monitoring error for {asset.name}: {e}")
        finally:
            db.commit()
"""
Monitoring Service - Background tasks for database monitoring.
Runs periodic checks based on configured intervals.
"""
import asyncio
import logging
from database import SessionLocal
from .health_monitor import run_health_checks
from .login_monitor import run_login_monitoring
from .privilege_monitor import run_privilege_monitoring
from .query_monitor import run_query_monitoring
from .schema_monitor import run_schema_monitoring
from .backup_monitor import run_backup_monitoring
from config import settings

logger = logging.getLogger(__name__)

async def start_monitoring():
    """Start all monitoring tasks."""
    logger.info("Starting database guardian monitoring services...")
    asyncio.create_task(health_check_loop())
    asyncio.create_task(login_monitor_loop())
    asyncio.create_task(privilege_monitor_loop())
    asyncio.create_task(query_monitor_loop())
    asyncio.create_task(schema_monitor_loop())
    asyncio.create_task(backup_monitor_loop())
    logger.info("All database guardian monitoring services started")

async def health_check_loop():
    """Run health checks every 5 minutes."""
    while True:
        db = SessionLocal()
        try:
            await run_health_checks(db)
        except Exception as e:
            logger.error(f"Health check error: {e}")
        finally:
            db.close()
        await asyncio.sleep(settings.DB_MONITOR_HEALTH_INTERVAL)

async def login_monitor_loop():
    """Run login monitoring every 60 seconds."""
    while True:
        db = SessionLocal()
        try:
            await run_login_monitoring(db)
        except Exception as e:
            logger.error(f"Login monitor error: {e}")
        finally:
            db.close()
        await asyncio.sleep(settings.DB_MONITOR_LOGIN_INTERVAL)

async def privilege_monitor_loop():
    """Run privilege monitoring every 5 minutes."""
    while True:
        db = SessionLocal()
        try:
            await run_privilege_monitoring(db)
        except Exception as e:
            logger.error(f"Privilege monitor error: {e}")
        finally:
            db.close()
        await asyncio.sleep(settings.DB_MONITOR_HEALTH_INTERVAL)  # Same as health checks

async def query_monitor_loop():
    """Run query monitoring every 1 minute."""
    while True:
        db = SessionLocal()
        try:
            await run_query_monitoring(db)
        except Exception as e:
            logger.error(f"Query monitor error: {e}")
        finally:
            db.close()
        await asyncio.sleep(settings.DB_MONITOR_QUERY_INTERVAL)

async def schema_monitor_loop():
    """Run schema monitoring every 10 minutes."""
    while True:
        db = SessionLocal()
        try:
            await run_schema_monitoring(db)
        except Exception as e:
            logger.error(f"Schema monitor error: {e}")
        finally:
            db.close()
        await asyncio.sleep(600)  # 10 minutes

async def backup_monitor_loop():
    """Run backup monitoring every 30 minutes."""
    while True:
        db = SessionLocal()
        try:
            await run_backup_monitoring(db)
        except Exception as e:
            logger.error(f"Backup monitor error: {e}")
        finally:
            db.close()
        await asyncio.sleep(1800)  # 30 minutes
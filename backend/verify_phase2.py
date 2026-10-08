"""
Verification script for Phase 2 Database Guardian implementation.
"""
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all new modules can be imported."""
    try:
        # Test config
        from config import settings
        print("✓ Config imported successfully")
        print(f"  DB_ENCRYPTION_KEY set: {bool(settings.DB_ENCRYPTION_KEY)}")
        print(f"  Health interval: {settings.DB_MONITOR_HEALTH_INTERVAL}s")
        print(f"  Login interval: {settings.DB_MONITOR_LOGIN_INTERVAL}s")
        print(f"  Query interval: {settings.DB_MONITOR_QUERY_INTERVAL}s")

        # Test models
        from models import DatabaseAsset, DatabaseHealthCheck, DatabaseLoginEvent
        print("✓ Database models imported successfully")

        # Test schemas
        from schemas import DatabaseAssetCreate, DatabaseAssetOut, DatabaseAlertOut
        print("✓ Database schemas imported successfully")

        # Test credential manager
        from database_guardian.credential_manager import credential_manager
        print("✓ Credential manager imported successfully")

        # Test db connector
        from database_guardian.db_connector import create_connector, SQLiteConnector, PostgreSQLConnector
        print("✓ Database connector imported successfully")

        # Test risk scorer
        from database_guardian.risk_scorer import calculate_database_risk_score, RISK_WEIGHTS
        print("✓ Risk scorer imported successfully")
        print(f"  Risk weights keys: {list(RISK_WEIGHTS.keys())}")

        # Test alert generator
        from database_guardian.alert_generator import create_database_alert
        print("✓ Alert generator imported successfully")

        # Test monitors
        from database_guardian.health_monitor import run_health_checks
        from database_guardian.login_monitor import run_login_monitoring
        from database_guardian.privilege_monitor import run_privilege_monitoring
        from database_guardian.query_monitor import run_query_monitoring
        from database_guardian.schema_monitor import run_schema_monitoring
        from database_guardian.backup_monitor import run_backup_monitoring
        print("✓ All monitoring modules imported successfully")

        # Test monitoring service
        from database_guardian.monitoring_service import start_monitoring
        print("✓ Monitoring service imported successfully")

        # Test API routes
        from api_routes import database_router
        print("✓ Database router imported successfully")

        print("\n🎉 All Phase 2 components imported successfully!")
        return True

    except Exception as e:
        print(f"\n❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
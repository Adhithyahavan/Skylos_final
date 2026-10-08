"""
Privilege Monitor - Track privilege changes and detect escalation.
"""
import asyncio
import logging
from sqlalchemy.orm import Session
from models import DatabaseAsset, DatabasePrivilegeChange, DatabaseUser
from .db_connector import create_connector
from datetime import datetime, timezone
from .alert_generator import create_database_alert
import json

logger = logging.getLogger(__name__)

async def run_privilege_monitoring(db: Session):
    """Monitor database privilege changes for escalation attempts."""
    assets = db.query(DatabaseAsset).filter(DatabaseAsset.is_active == True).all()

    for asset in assets:
        try:
            connector = create_connector(asset)
            conn = connector.connect()

            # Check for privilege changes (database-specific queries)
            if asset.db_type == "postgresql":
                try:
                    # Check for role membership changes, grants, etc.
                    # This is a simplified example - in production you'd want to
                    # audit PostgreSQL logs or use pg_audit extension
                    result = connector.execute_query("""
                        SELECT
                            rolname,
                            CASE
                                WHEN rolsuper THEN 'superuser'
                                WHEN rolcreaterole THEN 'can_create_roles'
                                WHEN rolcreatedb THEN 'can_create_db'
                                WHEN rolcanlogin THEN 'can_login'
                                ELSE 'no_special_privileges'
                            end as privileges
                        FROM pg_roles
                        WHERE rolname NOT IN ('pg_signal_backend', 'rdsadmin', 'pgaemon')
                    """)

                    # Track current users and their privileges
                    current_users = {}
                    for row in result:
                        username, privs = row
                        current_users[username] = privs

                    # Compare with known users in our database
                    known_users = db.query(DatabaseUser).filter(
                        DatabaseUser.database_id == asset.id
                    ).all()

                    known_user_dict = {user.username: user for user in known_users}

                    # Check for new users (potential account creation)
                    for username in current_users:
                        if username not in known_user_dict:
                            # New user detected
                            privilege_change = DatabasePrivilegeChange(
                                database_id=asset.id,
                                target_user=username,
                                change_type="create_user",
                                privilege="unknown",
                                granted_by="system"  # Would need to be determined from logs
                            )
                            db.add(privilege_change)

                            # Create alert for new admin/user creation
                            if "superuser" in current_users[username] or "can_create_roles" in current_users[username]:
                                await create_database_alert(
                                    db=db,
                                    database_id=asset.id,
                                    alert_type="db_new_admin",
                                    severity="high",
                                    title=f"New Admin/User Created in {asset.name}",
                                    description=f"User '{username}' created with elevated privileges",
                                    username=username,
                                    evidence={"privileges": current_users[username], "change_type": "create_user"}
                                )
                            else:
                                await create_database_alert(
                                    db=db,
                                    database_id=asset.id,
                                    alert_type="db_new_user",
                                    severity="medium",
                                    title=f"New User Created in {asset.name}",
                                    description=f"User '{username}' created",
                                    username=username,
                                    evidence={"privileges": current_users[username], "change_type": "create_user"}
                                )

                            # Add to known users
                            new_user = DatabaseUser(
                                database_id=asset.id,
                                username=username,
                                is_admin=("superuser" in current_users[username] or
                                        "can_create_roles" in current_users[username]),
                                privileges_json=json.dumps({"raw": current_users[username]})
                            )
                            db.add(new_user)

                    # Check for privilege changes in existing users
                    for username, privs in current_users.items():
                        if username in known_user_dict:
                            known_user = known_user_dict[username]
                            # Check if privileges changed
                            old_privs = known_user.privileges_json if known_user.privileges_json else "{}"
                            # Simplified check - in production you'd parse and compare properly
                            if str(current_users[username]) != old_privs.strip('{}'):
                                privilege_change = DatabasePrivilegeChange(
                                    database_id=asset.id,
                                    target_user=username,
                                    change_type="privilege_change",
                                    privilege=str(current_users[username]),
                                    granted_by="system"
                                )
                                db.add(privilege_change)

                                # Check for privilege escalation
                                was_admin = known_user.is_admin
                                is_admin = ("superuser" in current_users[username] or
                                          "can_create_roles" in current_users[username])

                                if not was_admin and is_admin:
                                    await create_database_alert(
                                        db=db,
                                        database_id=asset.id,
                                        alert_type="db_privilege_escalation",
                                        severity="critical",
                                        title=f"Privilege Escalation Detected in {asset.name}",
                                        description=f"User '{username}' gained admin privileges",
                                        username=username,
                                        evidence={
                                            "old_privileges": old_privs,
                                            "new_privileges": current_users[username],
                                            "change_type": "privilege_escalation"
                                        }
                                    )
                                elif was_admin != is_admin:
                                    await create_database_alert(
                                        db=db,
                                        database_id=asset.id,
                                        alert_type="db_privilege_change",
                                        severity="medium",
                                        title=f"Privilege Change for User in {asset.name}",
                                        description=f"User '{username}' privileges changed",
                                        username=username,
                                        evidence={
                                            "old_privileges": old_privs,
                                            "new_privileges": current_users[username],
                                            "change_type": "privilege_change"
                                        }
                                    )

                                # Update known user
                                known_user.is_admin = is_admin
                                known_user.privileges_json = json.dumps({"raw": current_users[username]})
                                known_user.last_seen = datetime.now(timezone.utc)

                except Exception as e:
                    logger.debug(f"Could not query pg_roles for {asset.name}: {e}")

            connector.close()

        except Exception as e:
            logger.error(f"Privilege monitoring error for {asset.name}: {e}")
        finally:
            db.commit()
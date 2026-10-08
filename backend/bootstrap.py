"""
Skylos — Administrator Bootstrap
First-run administrator creation and offline password reset.

There is no default administrator account. The first administrator is created
either from SKYLOS_BOOTSTRAP_ADMIN_* environment variables at startup, or with
`python manage.py create-admin`. Both paths refuse to run once any active
administrator exists, so bootstrap cannot be repeated to take over an install.
"""

import logging
import os
from typing import Optional

from sqlalchemy.orm import Session

from auth import hash_password, validate_password_strength
from models import AuditLog, User, UserRole

logger = logging.getLogger(__name__)


class BootstrapError(Exception):
    """Raised when an administrator bootstrap/reset request is refused."""


def admin_exists(db: Session) -> bool:
    return (
        db.query(User)
        .filter(User.role == UserRole.ADMIN.value, User.is_active == True)  # noqa: E712
        .first()
        is not None
    )


def create_initial_admin(db: Session, username: str, email: str, password: str, source: str) -> User:
    """Create the first administrator. Refuses if an active administrator exists."""
    if admin_exists(db):
        raise BootstrapError("An administrator already exists; bootstrap is disabled.")
    ok, msg = validate_password_strength(password)
    if not ok:
        raise BootstrapError(msg)
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        raise BootstrapError("A user with that username or email already exists.")

    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=UserRole.ADMIN.value,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.add(AuditLog(
        user_id=user.id,
        action="admin_bootstrap",
        details=f"Initial administrator {username} created via {source}",
    ))
    db.commit()
    logger.info("Initial administrator %s created via %s", username, source)
    return user


def reset_password(db: Session, username: str, password: str, source: str) -> User:
    """Reset a user's password. Intended for host-level (CLI) recovery only."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise BootstrapError(f"User {username!r} not found.")
    ok, msg = validate_password_strength(password)
    if not ok:
        raise BootstrapError(msg)
    user.hashed_password = hash_password(password)
    db.add(AuditLog(
        user_id=user.id,
        action="password_reset",
        details=f"Password for {username} reset via {source}",
    ))
    db.commit()
    logger.info("Password for %s reset via %s", username, source)
    return user


def bootstrap_admin_from_env(db: Session) -> Optional[User]:
    """
    Startup hook. Creates the first administrator from environment variables
    when no administrator exists; otherwise does nothing.
    """
    username = os.getenv("SKYLOS_BOOTSTRAP_ADMIN_USERNAME", "").strip()
    email = os.getenv("SKYLOS_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    password = os.getenv("SKYLOS_BOOTSTRAP_ADMIN_PASSWORD", "")

    if admin_exists(db):
        if password:
            logger.warning(
                "SKYLOS_BOOTSTRAP_ADMIN_PASSWORD is set but an administrator already exists; "
                "it is ignored. Remove it from the environment."
            )
        return None

    if not (username and email and password):
        logger.warning(
            "No administrator account exists. Create one with "
            "`python manage.py create-admin` or set SKYLOS_BOOTSTRAP_ADMIN_USERNAME, "
            "SKYLOS_BOOTSTRAP_ADMIN_EMAIL and SKYLOS_BOOTSTRAP_ADMIN_PASSWORD."
        )
        return None

    try:
        return create_initial_admin(db, username, email, password, source="environment bootstrap")
    except BootstrapError as e:
        logger.error("Administrator bootstrap from environment failed: %s", e)
        return None

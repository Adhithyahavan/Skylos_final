"""
AI-SIEM Guardian — Authentication Module
JWT-based auth with bcrypt password hashing and role-based access control.
Enhanced with rate limiting, token validation, and WebSocket authentication.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import hmac
import logging
import re

from fastapi import Depends, Header, HTTPException, status, WebSocket
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt, ExpiredSignatureError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import User, UserRole

logger = logging.getLogger(__name__)

# Passwords that earlier versions shipped as defaults. Accounts still using one
# are refused at login and must be reset with `python manage.py reset-password`.
LEGACY_DEFAULT_PASSWORDS = frozenset({"admin123"})

# ── Password hashing ────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── OAuth2 scheme ────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against the stored hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT token with the given payload and expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.JWT_EXPIRATION_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Validate expiration
        exp = payload.get("exp")
        if exp is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing expiration",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if token is expired
        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        # Do not echo library error text (it describes token internals)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """FastAPI dependency — resolve the current user from the bearer token."""
    payload = decode_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")
    return user


def require_role(*roles: str):
    """
    Returns a FastAPI dependency that enforces the user has one of the given roles.
    Usage: Depends(require_role("admin", "analyst"))
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {', '.join(roles)}",
            )
        return current_user
    return role_checker


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets minimum security requirements.
    Returns (is_valid, error_message)
    """
    if password in LEGACY_DEFAULT_PASSWORDS:
        return False, "Password is a known default and cannot be used"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if len(password) > 128:
        return False, "Password must be less than 128 characters"

    # Check for at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    # Check for at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    # Check for at least one digit
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"

    return True, ""


async def get_current_user_ws(websocket: WebSocket, db: Session) -> Optional[User]:
    """
    Authenticate WebSocket connections via token query parameter.
    Returns User if authenticated, None otherwise.
    Usage: user = await get_current_user_ws(websocket, db)
    """
    try:
        # Try to get token from query parameters
        token = websocket.query_params.get("token")
        if not token:
            return None

        # Decode and validate token
        payload = decode_token(token)
        username: str = payload.get("sub")
        if username is None:
            return None

        # Get user from database
        user = db.query(User).filter(User.username == username).first()
        if user is None or not user.is_active:
            return None

        return user
    except HTTPException:
        return None
    except Exception:
        return None


def verify_agent_key(api_key: str) -> bool:
    """
    Verify agent API key against configured key.
    Fails closed: if no key is configured, every agent request is rejected.
    Returns True if valid, False otherwise.
    """
    if not settings.AGENT_API_KEY:
        logger.warning("Agent request rejected: AGENT_API_KEY is not configured")
        return False
    if not api_key:
        return False
    return hmac.compare_digest(api_key.encode(), settings.AGENT_API_KEY.encode())


_optional_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def require_agent_or_role(*roles: str):
    """
    Dependency for endpoints callable by agents (X-API-Key) or by users with
    one of the given roles (Bearer JWT). Returns the User, or None for agents.
    """
    def checker(
        x_api_key: Optional[str] = Header(None),
        token: Optional[str] = Depends(_optional_oauth2_scheme),
        db: Session = Depends(get_db),
    ) -> Optional[User]:
        if x_api_key and verify_agent_key(x_api_key):
            return None
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = get_current_user(token, db)
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {', '.join(roles)}",
            )
        return user
    return checker

"""
Unit tests for the authentication module (real FastAPI / jose / passlib).

Previously this module replaced `fastapi` in sys.modules with mocks to work
around Python 3.7 dependency problems; that leaked into every other test module
and made real API tests impossible, so the tests now run against real code.
"""
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException
from jose import jwt

from auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    validate_password_strength,
    verify_agent_key,
    require_role,
    get_current_user_ws,
)
from config import settings


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password(self):
        password = "testpassword123"
        hashed = hash_password(password)
        assert hashed.startswith("$2b$")
        assert len(hashed) == 60
        assert verify_password(password, hashed) is True
        assert verify_password("wrongpassword", hashed) is False

    def test_verify_password_edge_cases(self):
        assert verify_password("", hash_password("")) is True
        with pytest.raises(Exception):
            verify_password(None, hash_password("test"))


class TestJWTTokenHandling:
    """Test JWT token creation and validation."""

    def test_create_and_decode_token(self):
        token = create_access_token({"sub": "testuser", "role": "admin"})
        assert isinstance(token, str) and token
        payload = decode_token(token)
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"
        assert "exp" in payload

    def test_token_expiration(self):
        token = create_access_token({"sub": "testuser"}, expires_delta=timedelta(seconds=-1))
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token has expired"

    def test_invalid_token(self):
        with pytest.raises(HTTPException) as exc_info:
            decode_token("invalid.token.string")
        assert exc_info.value.status_code == 401
        # Library error text must not be echoed to clients
        assert exc_info.value.detail == "Invalid token"

    def test_token_signed_with_other_key_rejected(self):
        forged = jwt.encode({"sub": "admin", "role": "admin", "exp": 9999999999},
                            "attacker-controlled-secret-0123456789abcdef", algorithm="HS256")
        with pytest.raises(HTTPException) as exc_info:
            decode_token(forged)
        assert exc_info.value.status_code == 401

    def test_unsigned_alg_none_token_rejected(self):
        # Hand-built "alg: none" token with no signature
        import base64
        import json

        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'admin', 'exp': 9999999999})}."
        with pytest.raises(HTTPException):
            decode_token(token)

    def test_token_without_expiration_rejected(self):
        token = jwt.encode({"sub": "testuser"}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.detail == "Token missing expiration"


class TestPasswordStrengthValidation:
    """Test password strength validation."""

    @pytest.mark.parametrize("password,expected_valid,expected_error", [
        ("short", False, "Password must be at least 8 characters long"),
        ("longpassword" * 20, False, "Password must be less than 128 characters"),
        ("lowercase123", False, "Password must contain at least one uppercase letter"),
        ("UPPERCASE123", False, "Password must contain at least one lowercase letter"),
        ("NoDigits!", False, "Password must contain at least one digit"),
        ("admin123", False, "Password is a known default and cannot be used"),
        ("ValidPass123", True, ""),
        ("AnotherValidPass456!", True, ""),
    ])
    def test_validate_password_strength(self, password, expected_valid, expected_error):
        is_valid, error_msg = validate_password_strength(password)
        assert is_valid == expected_valid
        assert error_msg == expected_error


class TestAgentKeyVerification:
    """Test agent API key verification."""

    def test_verify_agent_key_fails_closed_when_not_configured(self):
        # Previously an unset key allowed every agent; it must now reject all.
        with patch("auth.settings.AGENT_API_KEY", ""):
            assert verify_agent_key("any-key") is False
            assert verify_agent_key("") is False

    def test_verify_agent_key_when_configured(self):
        with patch("auth.settings.AGENT_API_KEY", "test-key-123"):
            assert verify_agent_key("test-key-123") is True
            assert verify_agent_key("wrong-key") is False
            assert verify_agent_key("") is False


class TestRoleBasedAccessControl:
    """Test role-based access control dependency."""

    def test_require_role_success(self):
        mock_user = Mock()
        mock_user.role = "admin"
        assert require_role("admin", "analyst")(mock_user) == mock_user

    def test_require_role_failure(self):
        mock_user = Mock()
        mock_user.role = "viewer"
        with pytest.raises(HTTPException) as exc_info:
            require_role("admin", "analyst")(mock_user)
        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in exc_info.value.detail
        assert "admin, analyst" in exc_info.value.detail


class TestWebSocketAuthentication:
    """Test WebSocket authentication helper."""

    @pytest.mark.asyncio
    async def test_get_current_user_ws_success(self):
        mock_websocket = Mock()
        mock_websocket.query_params = {"token": "valid-token"}
        mock_db = Mock()
        mock_user = Mock(username="testuser", is_active=True)
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        with patch("auth.decode_token", return_value={"sub": "testuser"}):
            assert await get_current_user_ws(mock_websocket, mock_db) == mock_user

    @pytest.mark.asyncio
    async def test_get_current_user_ws_missing_token(self):
        mock_websocket = Mock()
        mock_websocket.query_params = {}
        assert await get_current_user_ws(mock_websocket, Mock()) is None

    @pytest.mark.asyncio
    async def test_get_current_user_ws_invalid_token(self):
        mock_websocket = Mock()
        mock_websocket.query_params = {"token": "invalid-token"}
        assert await get_current_user_ws(mock_websocket, Mock()) is None

    @pytest.mark.asyncio
    async def test_get_current_user_ws_inactive_user(self):
        mock_websocket = Mock()
        mock_websocket.query_params = {"token": "valid-token"}
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = Mock(is_active=False)
        with patch("auth.decode_token", return_value={"sub": "testuser"}):
            assert await get_current_user_ws(mock_websocket, mock_db) is None

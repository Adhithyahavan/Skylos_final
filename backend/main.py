"""
AI-SIEM Guardian — Application Entry Point
FastAPI app with CORS, rate limiting, WebSocket, and startup seeding.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from database import init_db, SessionLocal
from auth import get_current_user_ws
from bootstrap import bootstrap_admin_from_env
from secret_provider import SecretProviderConfigError, validate_secret_provider
from websocket_manager import ws_manager
from api_routes import (
    auth_router, logs_router, alerts_router,
    network_router, dashboard_router, simulator_router,
    database_router, events_router,
)

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
)
logger = logging.getLogger("siem-guardian")

# ── Rate Limiter ─────────────────────────────────────────────────
# `config.py` loads the UTF-8 .env with python-dotenv. Disable SlowAPI's
# separate auto-read, which uses the Windows locale encoding and can fail on
# Unicode comments in that same file.
limiter = Limiter(key_func=get_remote_address, config_filename="")


# ── Security Headers Middleware ──────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if settings.ENABLE_SECURITY_HEADERS:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


# ── Lifespan (startup / shutdown) ────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs on startup: create tables + first-run administrator bootstrap."""
    logger.info("Skylos starting up")
    # Fail fast on a missing/invalid DB_ENCRYPTION_KEY instead of failing later
    # (or silently using a throwaway key) when credentials are encrypted.
    try:
        validate_secret_provider()
    except SecretProviderConfigError as e:
        logger.critical("Configuration error: %s", e)
        raise RuntimeError(f"Skylos cannot start: {e}") from None
    init_db()
    db = SessionLocal()
    try:
        bootstrap_admin_from_env(db)
    finally:
        db.close()
    if settings.DB_GUARDIAN_MONITORING_ENABLED:
        from database_guardian.monitoring_service import start_monitoring
        await start_monitoring()
    else:
        logger.info("Database Guardian background monitoring disabled by configuration")
    yield
    logger.info("Skylos shutting down")


# ── FastAPI App ──────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Lightweight AI-powered Cybersecurity Monitoring Platform",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register Routers ────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(network_router)
app.include_router(dashboard_router)
app.include_router(simulator_router)
app.include_router(database_router)
app.include_router(events_router)


# ── WebSocket Endpoint ──────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.
    Clients connect here to receive live alerts, logs, and network events.
    Requires authentication via token query parameter: /ws?token=<jwt_token>
    """
    db = SessionLocal()
    try:
        # Authenticate WebSocket connection
        user = await get_current_user_ws(websocket, db)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
            return

        await ws_manager.connect(websocket)
        logger.info(f"WebSocket connected: user={user.username}")

        try:
            while True:
                # Keep connection alive; client can also send messages
                data = await websocket.receive_text()
                # Echo back or handle client messages
                await ws_manager.send_personal({"type": "pong", "data": data, "user": user.username}, websocket)
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
            logger.info(f"WebSocket disconnected: user={user.username}")
    finally:
        db.close()


# ── Health Check ─────────────────────────────────────────────────
@app.get("/api/health")
def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }

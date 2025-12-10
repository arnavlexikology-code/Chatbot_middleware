"""
FastAPI Middleware Application Factory
=======================================

This is the main entry point for the middleware service that sits between
mobile clients (Android/iOS) and the backend agent gateway.

Architecture:
    Mobile Apps → Middleware (this service) → Backend → Copilot Studio Agent

Routers:
    - /auth/*       : Authentication flows (OIDC login, callback, token management)
    - /realtime/*   : WebSocket connections for live chat
    - /proxy/*      : Proxied requests to backend (requires valid JWT)
    - /health       : Health check endpoint

Environment Variables Required:
    - ALLOWED_ORIGINS: Comma-separated CORS origins (e.g., "http://localhost:19006,exp://192.168.1.100:8081")
    - BACKEND_URL: Backend service URL (e.g., "http://localhost:8000")
    - JWT_SECRET_KEY: Secret for signing session JWTs
    - JWT_ALGORITHM: JWT algorithm (default: HS256)
    - ENTRA_CLIENT_ID: Microsoft Entra ID application client ID
    - ENTRA_CLIENT_SECRET: Microsoft Entra ID client secret
    - ENTRA_TENANT_ID: Microsoft Entra ID tenant ID
    - ALLOWED_DOMAINS: Comma-separated email domains (e.g., "lithan.com,educlaas.com")
    - LOG_LEVEL: Logging level (default: INFO)

Running the Service:
    Development:
        uvicorn middleware.app.main:app --reload --host 0.0.0.0 --port 8080

    Production:
        uvicorn middleware.app.main:app --host 0.0.0.0 --port 8080 --workers 4

    With custom log level:
        LOG_LEVEL=DEBUG uvicorn middleware.app.main:app --reload

Dependencies:
    Ensure middleware/app/config.py, middleware/app/auth/routes.py,
    middleware/app/realtime/ws.py, and middleware/app/proxy/routes.py
    are implemented before running.
"""

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Import configuration - will be created if missing
try:
    from middleware.app.config import Settings, get_settings
except ImportError:
    # Fallback if config module doesn't exist yet
    from pydantic_settings import BaseSettings
    from functools import lru_cache

    class Settings(BaseSettings):
        """Minimal settings fallback"""
        allowed_origins: str = "http://localhost:19006"
        backend_url: str = "http://localhost:8000"
        jwt_secret_key: str = "change-me-in-production"
        jwt_algorithm: str = "HS256"
        entra_client_id: str = ""
        entra_client_secret: str = ""
        entra_tenant_id: str = ""
        allowed_domains: str = "lithan.com,educlaas.com"
        log_level: str = "INFO"

        class Config:
            env_file = ".env"
            case_sensitive = False

    @lru_cache()
    def get_settings() -> Settings:
        return Settings()

# Import routers - these will be implemented separately
try:
    from middleware.app.auth.routes import router as auth_router
except ImportError:
    # Placeholder if auth router not yet implemented
    from fastapi import APIRouter
    auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

    @auth_router.get("/placeholder")
    async def auth_placeholder():
        return {"message": "Auth router not yet implemented"}

try:
    from middleware.app.realtime.ws import realtime_router as ws_router
    from middleware.app.realtime.events import internal_router, typing_router
    # Combine both routers under /realtime prefix
    realtime_router = APIRouter(prefix="/realtime", tags=["Real-time"])
    realtime_router.include_router(ws_router)
    realtime_router.include_router(typing_router)
except ImportError:
    # Placeholder if realtime router not yet implemented
    from fastapi import APIRouter
    realtime_router = APIRouter(prefix="/realtime", tags=["Real-time"])
    internal_router = APIRouter(tags=["Internal"])

    @realtime_router.get("/placeholder")
    async def realtime_placeholder():
        return {"message": "Real-time router not yet implemented"}

try:
    from middleware.app.proxy.routes import router as proxy_router
except ImportError:
    # Placeholder if proxy router not yet implemented
    from fastapi import APIRouter
    proxy_router = APIRouter(prefix="/proxy", tags=["Backend Proxy"])

    @proxy_router.get("/placeholder")
    async def proxy_placeholder():
        return {"message": "Proxy router not yet implemented"}


# Configure structured JSON logging
def setup_logging(log_level: str = "INFO") -> None:
    """
    Configure structured logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s"}',
        handlers=[logging.StreamHandler(sys.stdout)]
    )


# Application state singletons
class AppState:
    """
    Global application state container.

    Holds shared resources like JWKS cache, WebSocket manager, etc.
    """
    def __init__(self):
        self.jwks_cache: Dict[str, Any] = {}
        self.realtime_manager: Any = None
        self.settings: Settings = None
        self.logger: logging.Logger = None


# Global state instance
app_state = AppState()


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Handles initialization on startup and cleanup on shutdown.

    Startup tasks:
        - Load configuration from environment
        - Initialize JWKS cache for JWT validation
        - Create RealtimeManager singleton for WebSocket connections
        - Log service startup information

    Shutdown tasks:
        - Close active WebSocket connections
        - Clear caches
        - Log shutdown information
    """
    # Startup
    settings = get_settings()
    app_state.settings = settings

    # Setup logging
    setup_logging(settings.log_level)
    logger = logging.getLogger("middleware.main")
    app_state.logger = logger

    logger.info(
        "Starting middleware service",
        extra={
            "backend_url": settings.backend_url,
            "allowed_domains": settings.allowed_domains,
            "log_level": settings.log_level
        }
    )

    # Initialize JWKS cache (for validating Entra ID tokens)
    app_state.jwks_cache = {
        "keys": [],
        "last_updated": None,
        "tenant_id": settings.entra_tenant_id
    }
    logger.info("Initialized JWKS cache for token validation")

    # Initialize RealtimeManager singleton for WebSocket management
    try:
        from middleware.app.realtime.manager import RealtimeManager
        from middleware.app.realtime.events import startup_event_cache

        app_state.realtime_manager = RealtimeManager()
        await app_state.realtime_manager.start()
        logger.info("Initialized RealtimeManager for WebSocket connections")
    except ImportError:
        logger.warning("RealtimeManager not yet implemented, WebSocket features will be unavailable")
        app_state.realtime_manager = None

    logger.info(
        "Middleware service started successfully",
        extra={
            "service": "middleware",
            "version": "1.0.0",
            "environment": "development"
        }
    )

    yield

    # Shutdown
    logger.info("Shutting down middleware service")

    # Close all WebSocket connections gracefully
    if app_state.realtime_manager:
        try:
            await app_state.realtime_manager.stop()
            logger.info("Stopped RealtimeManager and closed all connections")
        except Exception as e:
            logger.error(f"Error stopping RealtimeManager: {e}")

    # Clear caches
    app_state.jwks_cache.clear()
    logger.info("Cleared JWKS cache")

    logger.info("Middleware service shutdown complete")


# Create FastAPI application
def create_app() -> FastAPI:
    """
    Application factory function.

    Creates and configures the FastAPI application instance with:
        - Lifespan management
        - CORS middleware
        - Route handlers
        - Exception handlers

    Returns:
        FastAPI: Configured application instance
    """
    settings = get_settings()

    app = FastAPI(
        title="Middleware Service",
        description="Authentication and proxy middleware for mobile chatbot clients",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )

    # Configure CORS
    origins = [origin.strip() for origin in settings.allowed_origins.split(",")]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["*"]
    )

    # Mount routers
    # Auth router: Handles OIDC login, callback, token exchange, and user profile
    app.include_router(
        auth_router,
        prefix="/auth",
        tags=["Authentication"]
    )

    # Realtime router: Handles WebSocket connections for live chat
    app.include_router(
        realtime_router,
        tags=["Real-time Communications"]
    )

    # Internal router: Handles internal events from backend
    try:
        app.include_router(
            internal_router,
            tags=["Internal APIs"]
        )
    except NameError:
        pass  # internal_router not available

    # Proxy router: Forwards validated requests to backend agent gateway
    app.include_router(
        proxy_router,
        prefix="/proxy",
        tags=["Backend Proxy"]
    )

    # Health check endpoint
    @app.get("/health", tags=["System"])
    async def health_check() -> Dict[str, str]:
        """
        Health check endpoint.

        Returns service status and basic metadata.

        Returns:
            dict: Service health information
        """
        return {
            "status": "ok",
            "service": "middleware",
            "version": "1.0.0"
        }

    # Root endpoint
    @app.get("/", tags=["System"])
    async def root() -> Dict[str, str]:
        """
        Root endpoint with service information.

        Returns:
            dict: Service metadata and available endpoints
        """
        return {
            "service": "middleware",
            "version": "1.0.0",
            "description": "Authentication and proxy middleware for mobile chatbot clients",
            "endpoints": {
                "health": "/health",
                "docs": "/docs",
                "auth": "/auth",
                "realtime": "/realtime",
                "proxy": "/proxy"
            }
        }

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Global exception handler for unhandled errors.

        Logs the error and returns a standardized error response.

        Args:
            request: FastAPI request object
            exc: Exception that was raised

        Returns:
            JSONResponse: Standardized error response
        """
        logger = logging.getLogger("middleware.main")
        logger.error(
            f"Unhandled exception: {str(exc)}",
            extra={
                "path": request.url.path,
                "method": request.method,
                "exception_type": type(exc).__name__
            },
            exc_info=True
        )

        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message": "An unexpected error occurred",
                "detail": str(exc) if settings.log_level == "DEBUG" else None
            }
        )

    return app


# Create app instance for uvicorn
app = create_app()


# Make state accessible to routers via app.state
app.state.app_state = app_state


if __name__ == "__main__":
    """
    Direct execution entry point.
    
    This allows running the service directly with: python -m middleware.app.main
    However, using uvicorn command is recommended for production.
    """
    settings = get_settings()

    uvicorn.run(
        "middleware.app.main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level=settings.log_level.lower()
    )
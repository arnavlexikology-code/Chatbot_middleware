"""
Proxy Package
=============

This package implements authenticated proxy endpoints that forward
validated requests from mobile clients to the private backend service.

Main Components:
----------------
- routes.py: FastAPI router with proxy endpoints (/chat, /agent/status)

Security Features:
------------------
- JWT authentication enforcement
- Dangerous header stripping
- Internal secret header for backend authentication
- User claim forwarding

Usage:
------
    from app.proxy.routes import proxy_router
    app.include_router(proxy_router)
"""

from .routes import proxy_router

__all__ = ["proxy_router"]
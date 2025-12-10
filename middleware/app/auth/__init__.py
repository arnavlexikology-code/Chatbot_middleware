"""
Authentication Package

This package handles all authentication and authorization functionality
for the middleware service using Microsoft Entra ID and OpenID Connect (OIDC).

Key responsibilities:
- OIDC login flow initiation and callback handling
- ID token validation using JWKS from Microsoft Entra ID
- Domain-based access control (e.g., @lithan.com, @educlaas.com only)
- Session JWT issuance and validation for client applications
- Token refresh and user profile endpoints

Modules:
- routes: Public authentication endpoints (/auth/login, /auth/callback, etc.)
- utils: JWKS fetching, caching, and ID token verification utilities
- session: Session JWT creation and validation logic

The authentication flow:
1. Client initiates login via /auth/login
2. User authenticates with Microsoft Entra ID
3. Middleware receives ID token via /auth/callback
4. Middleware validates token, checks domain, issues session JWT
5. Client uses session JWT for subsequent API requests
"""

from .routes import auth_router

__all__ = [
    "auth_router",
]
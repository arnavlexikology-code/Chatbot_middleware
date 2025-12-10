"""
JWT Session Management Module
==============================

Handles creation and verification of session JWTs for the middleware layer.
Supports both HS256 (default) and RS256 algorithms.

This module combines the best features from both implementations:
- Robust error handling with HTTPException
- Support for both sync and async operations
- Token revocation support
- Comprehensive validation
- Production-ready configuration
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi import HTTPException, status, Header

# Import your settings/config module
try:
    from app.config import get_settings
    settings = get_settings()
except ImportError:
    # Fallback for testing/development
    from pydantic_settings import BaseSettings
    from functools import lru_cache

    class Settings(BaseSettings):
        SESSION_JWT_SECRET: str = "change-me-in-production"
        SESSION_JWT_EXPIRY_MINUTES: int = 60
        JWT_ALGORITHM: str = "HS256"
        JWT_ISSUER: str = "copilot-middleware"
        USE_RS256_JWT: bool = False
        JWT_PRIVATE_KEY: Optional[str] = None
        JWT_PUBLIC_KEY: Optional[str] = None

        class Config:
            env_file = ".env"

    @lru_cache()
    def get_settings():
        return Settings()
    
    settings = get_settings()

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class JWTSessionError(Exception):
    """Base exception for JWT session errors"""
    pass


# =============================================================================
# Token Creation
# =============================================================================

def create_session_jwt(claims: Dict[str, Any]) -> str:
    """
    Create a session JWT with the provided claims.
    
    Args:
        claims: Dictionary of claims to include in the JWT.
                Common claims: 'sub' (user ID), 'email', 'name', 'preferred_username'
    
    Returns:
        Encoded JWT string
    
    Raises:
        JWTSessionError: If JWT creation fails
    
    Example:
        >>> claims = {
        ...     'sub': 'user123',
        ...     'email': 'user@lithan.com',
        ...     'name': 'John Doe'
        ... }
        >>> token = create_session_jwt(claims)
    """
    try:
        # Create a copy to avoid mutating the input
        payload = claims.copy()
        
        # Add standard JWT claims
        now = datetime.now(timezone.utc)
        payload.update({
            'iat': now,  # Issued at
            'exp': now + timedelta(minutes=settings.SESSION_JWT_EXPIRY_MINUTES),
            'iss': settings.JWT_ISSUER,
        })
        
        # Validate required claims
        if 'sub' not in payload:
            raise JWTSessionError("Missing required claim: 'sub' (subject/user ID)")
        if 'email' not in payload:
            raise JWTSessionError("Missing required claim: 'email'")
        
        # Select algorithm and secret based on configuration
        algorithm = _get_algorithm()
        secret = _get_signing_key()
        
        # Encode the JWT
        token = jwt.encode(
            payload,
            secret,
            algorithm=algorithm
        )
        
        logger.debug(
            f"Created session JWT for user {payload.get('email')}",
            extra={
                "user_id": payload.get('sub'),
                "expires_in_minutes": settings.SESSION_JWT_EXPIRY_MINUTES
            }
        )
        
        return token
        
    except JWTSessionError:
        raise
    except Exception as e:
        logger.error(f"Failed to create session JWT: {e}", exc_info=True)
        raise JWTSessionError(f"Failed to create session JWT: {str(e)}") from e


async def create_session_jwt_async(
    claims: Dict[str, Any],
    expires_in_minutes: Optional[int] = None
) -> str:
    """
    Async version of create_session_jwt for compatibility.
    
    Args:
        claims: User claims to include in token
        expires_in_minutes: Optional custom expiry (overrides settings)
    
    Returns:
        Encoded JWT string
    """
    # Temporarily override expiry if provided
    original_expiry = settings.SESSION_JWT_EXPIRY_MINUTES
    if expires_in_minutes:
        settings.SESSION_JWT_EXPIRY_MINUTES = expires_in_minutes
    
    try:
        return create_session_jwt(claims)
    finally:
        settings.SESSION_JWT_EXPIRY_MINUTES = original_expiry


def create_session_jwt_from_id_token(
    id_token_claims: Dict[str, Any],
    email: str,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create session JWT from OIDC ID token claims.
    
    Extracts relevant claims from the ID token and creates a session JWT.
    Used in the auth callback flow after successful OIDC authentication.
    
    Args:
        id_token_claims: Claims from verified ID token
        email: User's email (already validated)
        additional_claims: Optional extra claims to include
    
    Returns:
        Session JWT string
    """
    session_claims = {
        'sub': id_token_claims.get('sub') or id_token_claims.get('oid'),
        'email': email,
        'name': id_token_claims.get('name', ''),
        'preferred_username': id_token_claims.get('preferred_username', email),
    }
    
    # Add any additional claims
    if additional_claims:
        session_claims.update(additional_claims)
    
    return create_session_jwt(session_claims)


# =============================================================================
# Token Verification
# =============================================================================

def verify_session_jwt(token: str) -> Dict[str, Any]:
    """
    Verify and decode a session JWT (synchronous).
    
    Args:
        token: JWT string to verify
    
    Returns:
        Dictionary containing the decoded claims
    
    Raises:
        HTTPException: With appropriate status code and detail
        
    Example:
        >>> token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
        >>> claims = verify_session_jwt(token)
        >>> user_email = claims.get('email')
    """
    if not token:
        logger.warning("Empty token provided for verification")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Select algorithm and secret based on configuration
        algorithm = _get_algorithm()
        secret = _get_verification_key()
        
        # Decode and verify the JWT
        decoded = jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'require': ['exp', 'iat', 'sub', 'email']
            }
        )
        
        # Verify issuer if configured
        if decoded.get('iss') != settings.JWT_ISSUER:
            logger.warning(f"Invalid token issuer: {decoded.get('iss')}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token issuer",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Optional: Check token revocation list
        # if await is_token_revoked(token):
        #     raise HTTPException(...)
        
        logger.debug(
            f"JWT verified successfully for user {decoded.get('email')}",
            extra={"user_id": decoded.get('sub')}
        )
        
        return decoded
        
    except ExpiredSignatureError:
        logger.warning("JWT token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token verification failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token verification failed"
        )


async def verify_session_jwt_async(token: str) -> Optional[Dict[str, Any]]:
    """
    Async version of verify_session_jwt.
    
    Returns None instead of raising exceptions for optional authentication.
    
    Args:
        token: JWT token string
    
    Returns:
        User claims if valid, None if invalid
    """
    try:
        return verify_session_jwt(token)
    except HTTPException:
        return None


# =============================================================================
# Helper Functions
# =============================================================================

def extract_token_from_header(authorization: Optional[str]) -> str:
    """
    Extract Bearer token from Authorization header.
    
    Args:
        authorization: Authorization header value
    
    Returns:
        Extracted token string
    
    Raises:
        HTTPException: If header format is invalid
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    parts = authorization.split()
    
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected: 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return parts[1]


def _get_algorithm() -> str:
    """Determine which JWT algorithm to use based on configuration."""
    return 'RS256' if settings.USE_RS256_JWT else 'HS256'


def _get_signing_key() -> str:
    """Get the appropriate signing key based on algorithm."""
    algorithm = _get_algorithm()
    
    if algorithm == 'RS256':
        if not settings.JWT_PRIVATE_KEY:
            raise JWTSessionError("RS256 enabled but JWT_PRIVATE_KEY not configured")
        return settings.JWT_PRIVATE_KEY
    else:
        if not settings.SESSION_JWT_SECRET:
            raise JWTSessionError("SESSION_JWT_SECRET not configured")
        return settings.SESSION_JWT_SECRET


def _get_verification_key() -> str:
    """Get the appropriate verification key based on algorithm."""
    algorithm = _get_algorithm()
    
    if algorithm == 'RS256':
        if not settings.JWT_PUBLIC_KEY:
            raise JWTSessionError("RS256 enabled but JWT_PUBLIC_KEY not configured")
        return settings.JWT_PUBLIC_KEY
    else:
        if not settings.SESSION_JWT_SECRET:
            raise JWTSessionError("SESSION_JWT_SECRET not configured")
        return settings.SESSION_JWT_SECRET


# =============================================================================
# FastAPI Dependencies
# =============================================================================

async def get_current_user(
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    FastAPI dependency to extract and verify JWT from request.
    
    Usage in routes:
        @app.get("/protected")
        async def protected_route(user: dict = Depends(get_current_user)):
            return {"user_email": user.get("email")}
    
    Args:
        authorization: Authorization header (automatically injected)
    
    Returns:
        Decoded user claims
    
    Raises:
        HTTPException: If authentication fails
    """
    token = extract_token_from_header(authorization)
    return verify_session_jwt(token)


async def get_optional_user(
    authorization: Optional[str] = Header(None)
) -> Optional[Dict[str, Any]]:
    """
    FastAPI dependency for optional authentication.
    
    Returns user claims if valid token provided, None otherwise.
    
    Usage:
        @app.get("/optional-auth")
        async def route(user: Optional[dict] = Depends(get_optional_user)):
            if user:
                return {"message": f"Hello {user['email']}"}
            return {"message": "Hello anonymous"}
    """
    if not authorization:
        return None
    
    try:
        token = extract_token_from_header(authorization)
        return verify_session_jwt(token)
    except HTTPException:
        return None


# =============================================================================
# Token Revocation (Stub)
# =============================================================================

# Token revocation list (in-memory, use Redis in production)
_revoked_tokens = set()


async def revoke_session_jwt(token: str) -> bool:
    """
    Revoke a JWT session token.
    
    In production, implement with Redis or database:
    - Add token JTI to blacklist
    - Set expiry to match token expiry
    - Check blacklist in verify_session_jwt
    
    Args:
        token: JWT token to revoke
    
    Returns:
        True if revoked successfully
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        token_id = decoded.get('jti') or token[:32]  # Use JTI or token prefix
        _revoked_tokens.add(token_id)
        
        logger.info(f"Revoked token for user {decoded.get('sub')}")
        return True
    except Exception as e:
        logger.error(f"Failed to revoke token: {e}")
        return False


async def is_token_revoked(token: str) -> bool:
    """
    Check if token is in revocation list.
    
    Args:
        token: JWT token to check
    
    Returns:
        True if token is revoked
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        token_id = decoded.get('jti') or token[:32]
        return token_id in _revoked_tokens
    except:
        return False


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Creation
    "create_session_jwt",
    "create_session_jwt_async",
    "create_session_jwt_from_id_token",
    
    # Verification
    "verify_session_jwt",
    "verify_session_jwt_async",
    
    # Helpers
    "extract_token_from_header",
    
    # Dependencies
    "get_current_user",
    "get_optional_user",
    
    # Revocation
    "revoke_session_jwt",
    "is_token_revoked",
    
    # Exceptions
    "JWTSessionError",
]

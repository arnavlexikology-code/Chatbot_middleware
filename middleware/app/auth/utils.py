"""
Authentication utilities for OIDC token verification and JWKS management.

This module handles:
- Fetching and caching Azure AD JWKS (JSON Web Key Set)
- Verifying ID tokens from Microsoft Entra ID
- Validating token claims and signatures
"""

import time
from typing import Dict, Any, Optional
from datetime import datetime, timezone

import httpx
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode

from app.config import get_settings


# =============================================================================
# JWKS Cache
# =============================================================================

_jwks_cache: Optional[Dict[str, Any]] = None
_jwks_cache_time: float = 0.0


async def fetch_jwks(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Fetch JWKS from Azure AD with caching.
    
    The JWKS endpoint provides public keys used to verify JWT signatures.
    Results are cached based on JWKS_CACHE_SECONDS setting.
    
    Args:
        force_refresh: If True, bypass cache and fetch fresh JWKS
        
    Returns:
        JWKS document containing keys
        
    Raises:
        httpx.HTTPError: If JWKS endpoint is unreachable
        ValueError: If response is invalid
    """
    global _jwks_cache, _jwks_cache_time
    
    settings = get_settings()
    current_time = time.time()
    cache_ttl = settings.JWKS_CACHE_SECONDS
    
    # Return cached JWKS if still valid
    if not force_refresh and _jwks_cache and (current_time - _jwks_cache_time) < cache_ttl:
        return _jwks_cache
    
    # Fetch fresh JWKS
    jwks_uri = f"{settings.azure_authority}/discovery/v2.0/keys"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_uri, timeout=10.0)
        response.raise_for_status()
        
        jwks_data = response.json()
        
        if "keys" not in jwks_data:
            raise ValueError("Invalid JWKS response: missing 'keys' field")
        
        # Update cache
        _jwks_cache = jwks_data
        _jwks_cache_time = current_time
        
        return jwks_data


def get_signing_key(token: str, jwks: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract the public key from JWKS that matches the token's kid.
    
    Args:
        token: JWT token string
        jwks: JWKS document containing keys
        
    Returns:
        Matching key from JWKS, or None if not found
        
    Raises:
        JWTError: If token header is malformed
    """
    # Decode header without verification to get kid
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise JWTError(f"Failed to decode token header: {e}")
    
    kid = unverified_header.get("kid")
    if not kid:
        raise JWTError("Token header missing 'kid' (Key ID)")
    
    # Find matching key in JWKS
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    
    return None


async def verify_id_token(id_token: str) -> Dict[str, Any]:
    """
    Verify and decode an ID token from Azure AD.
    
    This function performs comprehensive validation:
    1. Fetches JWKS and finds the correct public key
    2. Verifies the token signature
    3. Validates standard claims (iss, aud, exp, nbf, iat)
    4. Returns decoded claims
    
    Args:
        id_token: JWT ID token string from Azure AD
        
    Returns:
        Dictionary of verified token claims
        
    Raises:
        JWTError: If token is invalid, expired, or signature doesn't match
        ValueError: If required claims are missing or invalid
        httpx.HTTPError: If JWKS endpoint is unreachable
    """
    settings = get_settings()
    
    # Fetch JWKS
    jwks = await fetch_jwks()
    
    # Get the signing key
    signing_key = get_signing_key(id_token, jwks)
    if not signing_key:
        # Try refreshing JWKS in case keys were rotated
        jwks = await fetch_jwks(force_refresh=True)
        signing_key = get_signing_key(id_token, jwks)
        
        if not signing_key:
            raise JWTError(
                "Unable to find matching signing key in JWKS. "
                "Token may be from a different tenant or keys may have rotated."
            )
    
    # Convert JWK to PEM format for verification
    try:
        public_key = jwk.construct(signing_key)
    except Exception as e:
        raise JWTError(f"Failed to construct public key from JWK: {e}")
    
    # Verify and decode token
    try:
        claims = jwt.decode(
            id_token,
            public_key.to_pem().decode('utf-8'),
            algorithms=["RS256"],
            audience=settings.AZURE_CLIENT_ID,
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iat": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_sub": True,
                "verify_jti": False,
                "verify_at_hash": False,
                "leeway": 10,  # 10 seconds clock skew tolerance
            }
        )
    except jwt.ExpiredSignatureError:
        raise JWTError("ID token has expired")
    except jwt.JWTClaimsError as e:
        raise JWTError(f"Invalid token claims: {e}")
    except JWTError as e:
        raise JWTError(f"Token verification failed: {e}")
    
    # Validate issuer
    issuer = claims.get("iss", "")
    if not issuer.startswith("https://login.microsoftonline.com/"):
        raise ValueError(
            f"Invalid issuer: {issuer}. "
            "Token must be issued by Microsoft Entra ID"
        )
    
    # Validate tenant
    if settings.AZURE_TENANT_ID not in issuer:
        raise ValueError(
            f"Token issued by wrong tenant. Expected {settings.AZURE_TENANT_ID}"
        )
    
    return claims


def extract_email_from_claims(claims: Dict[str, Any]) -> Optional[str]:
    """
    Extract email address from ID token claims.
    
    Azure AD may use different claim names depending on configuration:
    - preferred_username: Usually the UPN (user@domain.com)
    - upn: User Principal Name
    - email: Email address
    - unique_name: Alternative identifier
    
    Args:
        claims: Decoded ID token claims
        
    Returns:
        Email address if found, None otherwise
    """
    # Try different claim names in order of preference
    for claim_name in ["preferred_username", "upn", "email", "unique_name"]:
        email = claims.get(claim_name)
        if email and "@" in email:
            return email.lower().strip()
    
    return None


def validate_email_domain(email: str, allowed_domains: list) -> bool:
    """
    Check if email domain is in the allowed list.
    
    Args:
        email: Email address to validate
        allowed_domains: List of allowed domain strings
        
    Returns:
        True if email domain is allowed, False otherwise
    """
    if not email or "@" not in email:
        return False
    
    domain = email.split("@")[-1].lower().strip()
    return domain in [d.lower() for d in allowed_domains]


def get_user_display_name(claims: Dict[str, Any]) -> str:
    """
    Extract user's display name from claims.
    
    Args:
        claims: Decoded ID token claims
        
    Returns:
        Display name or email as fallback
    """
    name = claims.get("name") or claims.get("given_name")
    if name:
        return name
    
    email = extract_email_from_claims(claims)
    if email:
        return email.split("@")[0].title()
    
    return "User"


# =============================================================================
# Token Validation Helpers
# =============================================================================

def validate_nonce(claims: Dict[str, Any], expected_nonce: Optional[str]) -> bool:
    """
    Validate nonce claim if present.
    
    Args:
        claims: Token claims
        expected_nonce: Expected nonce value from session
        
    Returns:
        True if nonce is valid or not required, False if mismatch
    """
    token_nonce = claims.get("nonce")
    
    # If no nonce in token and none expected, OK
    if not token_nonce and not expected_nonce:
        return True
    
    # If nonce present, must match
    if token_nonce and expected_nonce:
        return token_nonce == expected_nonce
    
    # Mismatch
    return False


def validate_state(received_state: str, expected_state: str) -> bool:
    """
    Validate OAuth state parameter.
    
    Args:
        received_state: State from callback
        expected_state: State from session
        
    Returns:
        True if states match
    """
    return received_state == expected_state


# =============================================================================
# Debugging and Inspection
# =============================================================================

def decode_token_without_verification(token: str) -> Dict[str, Any]:
    """
    Decode a JWT without verifying signature (for debugging only).
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded claims (unverified)
        
    Raises:
        JWTError: If token is malformed
    """
    return jwt.get_unverified_claims(token)


def get_token_expiry(claims: Dict[str, Any]) -> Optional[datetime]:
    """
    Extract expiry datetime from token claims.
    
    Args:
        claims: Decoded token claims
        
    Returns:
        Expiry datetime in UTC, or None if not present
    """
    exp = claims.get("exp")
    if exp:
        return datetime.fromtimestamp(exp, tz=timezone.utc)
    return None


def is_token_expired(claims: Dict[str, Any], leeway_seconds: int = 10) -> bool:
    """
    Check if token is expired.
    
    Args:
        claims: Decoded token claims
        leeway_seconds: Clock skew tolerance
        
    Returns:
        True if token is expired
    """
    exp = claims.get("exp")
    if not exp:
        return True
    
    current_time = time.time()
    return current_time > (exp + leeway_seconds)
"""
Proxy Routes - Backend Request Forwarding
==========================================

This module implements authenticated proxy endpoints that forward validated
requests from mobile clients to the private backend service.

Security Model:
---------------
1. All requests must include valid session JWT (obtained after OIDC auth)
2. Middleware validates JWT and extracts user claims
3. Middleware adds internal secret header (X-Internal-Secret) for backend auth
4. Authorization header is explicitly dropped (not forwarded)
5. Backend trusts requests from middleware based on internal secret

Endpoints:
----------
- POST /chat: Forward chat messages to backend agent
"""

import asyncio
import logging
import uuid
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
import httpx

from ..config import get_settings
from ..auth.session import verify_session_jwt, extract_token_from_header

logger = logging.getLogger(__name__)

# Create router
proxy_router = APIRouter()


# ============================================================================
# Request/Response Models
# ============================================================================

class ChatRequest(BaseModel):
    """
    Chat request payload from mobile client.
    
    Attributes:
        message: User's message text
        conversationId: Unique conversation identifier (auto-generated if missing)
        metadata: Optional metadata (user preferences, context, etc.)
    """
    
    message: str = Field(
        ...,
        description="User's message text",
        min_length=1,
        max_length=4000
    )
    
    conversationId: Optional[str] = Field(
        default=None,
        description="Conversation identifier (UUID format preferred)"
    )
    
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional metadata for the conversation"
    )
    
    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        """Validate and sanitize message"""
        # Strip whitespace
        v = v.strip()
        if not v:
            raise ValueError("Message cannot be empty or only whitespace")
        return v
    
    @field_validator("conversationId")
    @classmethod
    def validate_conversation_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate conversation ID format if provided"""
        if v is not None:
            v = v.strip()
            if not v:
                return None
            # Optionally validate UUID format
            try:
                uuid.UUID(v)
            except ValueError:
                # Allow non-UUID conversation IDs but log warning
                logger.warning("Non-UUID conversation ID provided")
        return v


# ============================================================================
# Dependencies
# ============================================================================

async def get_user_claims(request: Request) -> Dict[str, Any]:
    """
    Dependency to verify session JWT and extract user claims.
    
    Uses verify_session_jwt from middleware.auth.session.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Dict containing user claims (sub, email, etc.)
    
    Raises:
        HTTPException: If token is missing, invalid, or expired
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = extract_token_from_header(auth_header)
    return verify_session_jwt(token)


def get_backend_client(request: Request) -> httpx.AsyncClient:
    """
    Dependency to get backend HTTP client from app state.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Configured httpx.AsyncClient for backend communication
    """
    if not hasattr(request.app.state, "app_state"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend client not initialized"
        )
    
    client = request.app.state.app_state.backend_client
    if not client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend client not available"
        )
    
    return client


# ============================================================================
# Header Security Functions
# ============================================================================

def build_backend_headers(
    settings,
    original_headers: Dict[str, str]
) -> Dict[str, str]:
    """
    Build headers for backend request.
    
    Explicitly drops Authorization header and adds X-Internal-Secret.
    
    Args:
        settings: Application settings
        original_headers: Original request headers
    
    Returns:
        Headers dict for backend request
    
    Raises:
        HTTPException: If INTERNAL_SHARED_SECRET is not configured
    """
    # Validate INTERNAL_SHARED_SECRET is configured
    if not settings.INTERNAL_SHARED_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="INTERNAL_SHARED_SECRET not configured"
        )
    
    # Start with safe headers (explicitly exclude Authorization)
    safe_headers = {
        k: v for k, v in original_headers.items()
        if k.lower() != "authorization"
    }
    
    # Add internal authentication header
    backend_headers = {
        "X-Internal-Secret": settings.INTERNAL_SHARED_SECRET,
        "Content-Type": "application/json",
    }
    
    # Merge with safe headers (backend headers take precedence)
    safe_headers.update(backend_headers)
    
    return safe_headers


# ============================================================================
# Proxy Endpoints
# ============================================================================

@proxy_router.post("/chat")
async def proxy_chat(
    request: Request,
    chat_request: ChatRequest,
    user_claims: Dict[str, Any] = Depends(get_user_claims),
    backend_client: httpx.AsyncClient = Depends(get_backend_client)
):
    """
    Proxy chat message to backend agent.
    
    Flow:
    1. Validate session JWT (done by dependency)
    2. Validate and sanitize request payload
    3. Generate conversationId if missing
    4. Forward request to backend with internal secret header
    5. Retry on 5xx responses (2 attempts with exponential backoff)
    6. Return backend response to client
    
    Args:
        request: FastAPI request
        chat_request: Validated chat request payload
        user_claims: User claims from verified JWT
        backend_client: HTTP client for backend communication
    
    Returns:
        JSON response from backend agent (unchanged)
    
    Raises:
        HTTPException: Various error conditions
    """
    settings = get_settings()
    
    # Generate conversation ID if not provided
    if not chat_request.conversationId:
        chat_request.conversationId = str(uuid.uuid4())
        logger.info("Generated new conversation ID")
    
    # Build payload for backend
    backend_payload = {
        "message": chat_request.message,
        "conversationId": chat_request.conversationId,
        "user": {
            "sub": user_claims.get("sub"),
            "email": user_claims.get("email")
        }
    }
    
    # Build backend request headers (explicitly drop Authorization)
    backend_headers = build_backend_headers(settings, dict(request.headers))
    
    # Log request details (without sensitive data)
    logger.info(
        "Proxying chat request to backend",
        extra={
            "conversation_id": chat_request.conversationId,
            "user_email": user_claims.get("email"),
            "message_length": len(chat_request.message),
        }
    )
    
    # Configure timeout
    timeout = httpx.Timeout(30.0, connect=10.0)
    
    # Retry configuration: 2 attempts with exponential backoff (0.5s -> 1.5s)
    max_attempts = 2
    backoff_delays = [0.5, 1.5]
    
    for attempt in range(max_attempts):
        try:
            # Forward request to backend
            response = await backend_client.post(
                "/agent/chat",
                json=backend_payload,
                headers=backend_headers,
                timeout=timeout
            )
            
            # Handle backend response
            if response.status_code == 200:
                # Return backend JSON body unchanged
                return response.json()
            
            elif response.status_code >= 500:
                # 5xx error - retry if we have attempts left
                if attempt < max_attempts - 1:
                    delay = backoff_delays[attempt]
                    logger.warning(
                        f"Backend 5xx error (attempt {attempt + 1}/{max_attempts}), retrying after {delay}s",
                        extra={
                            "status_code": response.status_code,
                            "conversation_id": chat_request.conversationId
                        }
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    # All retries exhausted
                    logger.error(
                        f"Backend server error after {max_attempts} attempts: {response.status_code}",
                        extra={"conversation_id": chat_request.conversationId}
                    )
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Backend service temporarily unavailable"
                    )
            
            elif response.status_code == 401:
                # Backend rejected internal secret
                logger.error("Backend authentication failed - invalid internal secret")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Backend service authentication failed"
                )
            
            elif response.status_code == 429:
                # Rate limited by backend
                logger.warning("Backend rate limit exceeded")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests, please try again later"
                )
            
            else:
                # Other client errors from backend
                logger.warning(f"Backend client error: {response.status_code}")
                error_detail = response.json() if response.text else {"error": "Unknown error"}
                raise HTTPException(
                    status_code=response.status_code,
                    detail=error_detail.get("detail", "Backend request failed")
                )
        
        except httpx.HTTPStatusError as e:
            # Handle HTTP status errors
            if e.response.status_code >= 500:
                # 5xx error - retry if we have attempts left
                if attempt < max_attempts - 1:
                    delay = backoff_delays[attempt]
                    logger.warning(
                        f"Backend 5xx error (attempt {attempt + 1}/{max_attempts}), retrying after {delay}s",
                        extra={
                            "status_code": e.response.status_code,
                            "conversation_id": chat_request.conversationId
                        }
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    # All retries exhausted
                    logger.error(
                        f"Backend server error after {max_attempts} attempts: {e.response.status_code}",
                        extra={"conversation_id": chat_request.conversationId}
                    )
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail="Backend service temporarily unavailable"
                    )
            else:
                # Non-5xx HTTP error, don't retry
                raise
        
        except httpx.TimeoutException:
            logger.error(
                "Backend request timeout",
                extra={"conversation_id": chat_request.conversationId}
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Backend service timeout - please try again"
            )
        
        except httpx.NetworkError as e:
            logger.error(
                f"Backend network error: {e}",
                extra={"conversation_id": chat_request.conversationId}
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cannot reach backend service"
            )
        
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        
        except Exception as e:
            logger.error(
                f"Unexpected error in proxy_chat: {e}",
                exc_info=True,
                extra={
                    "conversation_id": chat_request.conversationId,
                    "user_email": user_claims.get("email")
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

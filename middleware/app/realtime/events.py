"""
Realtime Events Module

This module provides internal event publishing endpoints and TTL-based
typing state management for WebSocket communication.

Key responsibilities:
- Accept internal events from backend services (e.g., assistant typing indicators)
- Maintain a TTL-based cache of typing states per conversation
- Publish events to WebSocket rooms/connections
- Expose typing state queries for client polling (if needed)
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import APIRouter, Request, HTTPException, Header, Query, status
from pydantic import BaseModel, Field

from ..config import get_settings
from .ws import realtime_manager

logger = logging.getLogger("middleware.realtime.events")

# Router for internal event endpoints (backend -> middleware)
internal_router = APIRouter(tags=["internal"])

# Router for public typing state queries
typing_router = APIRouter(tags=["realtime"])


# ============================================================================
# TTL Typing State Cache
# ============================================================================

class TypingStateCache:
    """
    In-memory TTL cache for typing states per conversation.
    
    Thread-safe implementation using asyncio.Lock.
    """
    
    def __init__(self, ttl_seconds: int = 5):
        """
        Initialize typing state cache.
        
        Args:
            ttl_seconds: Time-to-live for typing states in seconds (default: 5)
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._ttl_seconds = ttl_seconds
    
    async def set_typing(
        self,
        conversation_id: str,
        typing_state: Dict[str, Any]
    ) -> None:
        """
        Store typing state for a conversation with TTL.
        
        Args:
            conversation_id: Conversation identifier
            typing_state: Typing state data to store
        """
        async with self._lock:
            expires_at = datetime.utcnow() + timedelta(seconds=self._ttl_seconds)
            self._cache[conversation_id] = {
                **typing_state,
                "expires_at": expires_at.isoformat(),
                "conversationId": conversation_id
            }
            logger.debug(
                f"Set typing state for conversation {conversation_id}, expires at {expires_at}"
            )
    
    async def remove_typing(self, conversation_id: str) -> None:
        """
        Remove typing state for a conversation.
        
        Args:
            conversation_id: Conversation identifier
        """
        async with self._lock:
            if conversation_id in self._cache:
                del self._cache[conversation_id]
                logger.debug(f"Removed typing state for conversation {conversation_id}")
    
    async def get_typing(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get typing state for a conversation if it exists and hasn't expired.
        
        Automatically removes expired entries.
        
        Args:
            conversation_id: Conversation identifier
            
        Returns:
            Typing state dict if found and not expired, None otherwise
        """
        async with self._lock:
            # Clean up expired entries first
            now = datetime.utcnow()
            expired_keys = []
            
            for key, value in self._cache.items():
                expires_at_str = value.get("expires_at")
                if expires_at_str:
                    try:
                        # Parse ISO format timestamp (UTC, no timezone)
                        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", ""))
                        # Compare naive UTC datetimes
                        if now >= expires_at:
                            expired_keys.append(key)
                    except (ValueError, AttributeError):
                        # Invalid date format, mark as expired
                        expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
                logger.debug(f"Removed expired typing state for conversation {key}")
            
            # Return requested state if it exists
            state = self._cache.get(conversation_id)
            if state:
                # Remove expires_at from returned state
                result = {k: v for k, v in state.items() if k != "expires_at"}
                return result
            
            return None


# Global typing state cache instance
typing_cache = TypingStateCache(ttl_seconds=5)


# ============================================================================
# Event Models
# ============================================================================

class InternalEventPayload(BaseModel):
    """Event payload model for internal events."""
    type: str = Field(..., description="Event type (e.g., 'assistant.typing.start')")
    conversationId: str = Field(..., description="Target conversation identifier")
    requestId: Optional[str] = Field(None, description="Optional request identifier")
    timestamp: Optional[str] = Field(None, description="Optional event timestamp (ISO format)")
    partialText: Optional[str] = Field(None, description="Optional partial text for typing events")


# ============================================================================
# Internal Event Endpoint
# ============================================================================

@internal_router.post("/internal/events")
async def publish_event(
    request: Request,
    event: InternalEventPayload,
    x_internal_secret: Optional[str] = Header(None, alias="X-Internal-Secret")
) -> Dict[str, Any]:
    """
    Receive internal events from backend services.
    
    Validates X-Internal-Secret header and publishes events to WebSocket subscribers.
    Manages typing state cache for assistant typing events.
    
    Expected event types:
    - assistant.typing.start: Start typing indicator (stores in cache with TTL)
    - assistant.typing.progress: Update typing indicator (stores in cache with TTL)
    - assistant.typing.end: End typing indicator (removes from cache)
    - Other event types: Published to WebSocket but not cached
    
    Args:
        request: FastAPI request object
        event: Event payload
        x_internal_secret: X-Internal-Secret header value
        
    Returns:
        Acknowledgment of event receipt
        
    Raises:
        HTTPException: 401 if secret is missing or invalid
    """
    settings = get_settings()
    
    # Validate internal secret
    if not x_internal_secret or x_internal_secret != settings.INTERNAL_SHARED_SECRET:
        logger.warning(
            "Internal event rejected: invalid or missing X-Internal-Secret header",
            extra={"path": request.url.path}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing X-Internal-Secret header"
        )
    
    # Prepare event for publishing
    event_dict = event.dict(exclude_none=True)
    
    # Add timestamp if not provided
    if "timestamp" not in event_dict or not event_dict["timestamp"]:
        event_dict["timestamp"] = datetime.utcnow().isoformat()
    
    event_type = event_dict.get("type", "")
    conversation_id = event_dict.get("conversationId")
    
    # Handle typing state cache for assistant typing events
    if event_type in ("assistant.typing.start", "assistant.typing.progress"):
        # Store typing state with TTL
        typing_state = {
            "typingState": {
                "isTyping": True,
                "requestId": event_dict.get("requestId"),
                "timestamp": event_dict.get("timestamp"),
                "partialText": event_dict.get("partialText")
            }
        }
        await typing_cache.set_typing(conversation_id, typing_state)
        logger.info(
            f"Updated typing state for conversation {conversation_id}",
            extra={"event_type": event_type, "conversation_id": conversation_id}
        )
    
    elif event_type == "assistant.typing.end":
        # Remove typing state
        await typing_cache.remove_typing(conversation_id)
        logger.info(
            f"Removed typing state for conversation {conversation_id}",
            extra={"conversation_id": conversation_id}
        )
    
    # Publish event to WebSocket subscribers
    recipients = await realtime_manager.publish(event_dict)
    
    logger.info(
        f"Published internal event",
        extra={
            "event_type": event_type,
            "conversation_id": conversation_id,
            "recipients": recipients
        }
    )
    
    return {
        "status": "received",
        "event_type": event_type,
        "conversation_id": conversation_id,
        "recipients": recipients
    }


# ============================================================================
# Typing State Query Endpoint
# ============================================================================

@typing_router.get("/realtime/typing")
async def get_typing_state(
    conversationId: Optional[str] = Query(None, description="Conversation identifier")
) -> Dict[str, Any]:
    """
    Query current typing state for a conversation.
    
    This endpoint allows clients to poll for typing indicators if
    WebSocket connections are unavailable or as a fallback mechanism.
    
    The typing state is maintained in a TTL-based cache where entries
    automatically expire after 5 seconds.
    
    Args:
        conversationId: Conversation identifier to query
        
    Returns:
        Typing state dict with conversationId and typingState if found,
        or empty dict if not found or expired
    """
    if not conversationId:
        return {}
    
    state = await typing_cache.get_typing(conversationId)
    
    if state:
        return state
    
    return {}


# Export routers
__all__ = ["internal_router", "typing_router"]

"""
Data Models Module

This module defines Pydantic models for request/response validation
and data serialization throughout the middleware service.

Models are organized by functional area:
- Authentication models (login requests, token responses, user profiles)
- Chat/messaging models (chat requests, responses, message formats)
- WebSocket models (connection events, typing indicators)
- Internal event models (backend event payloads)
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any, List
from datetime import datetime


# ============================================================================
# Authentication Models
# ============================================================================

class LoginRequest(BaseModel):
    """Request model for initiating OIDC login flow."""
    redirect_uri: Optional[str] = Field(None, description="Optional redirect URI after login")


class TokenResponse(BaseModel):
    """Response model containing session JWT and metadata."""
    access_token: str = Field(..., description="Session JWT token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class UserProfile(BaseModel):
    """User profile information extracted from validated ID token."""
    user_id: str = Field(..., description="Unique user identifier")
    email: EmailStr = Field(..., description="User email address")
    name: Optional[str] = Field(None, description="User display name")
    domain: str = Field(..., description="Email domain for access control")


class RefreshRequest(BaseModel):
    """Request model for token refresh."""
    refresh_token: Optional[str] = Field(None, description="Refresh token if supported")


# ============================================================================
# Chat/Messaging Models
# ============================================================================

class ChatRequest(BaseModel):
    """Request model for sending a chat message."""
    message: str = Field(..., description="User message content", min_length=1)
    conversation_id: Optional[str] = Field(None, description="Conversation identifier for continuity")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional message metadata")


class ChatResponse(BaseModel):
    """Response model for chat message replies."""
    conversation_id: str = Field(..., description="Conversation identifier")
    reply: str = Field(..., description="Assistant response text")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional response metadata")


class MessageBubble(BaseModel):
    """Individual message in a conversation."""
    id: str = Field(..., description="Unique message identifier")
    sender: str = Field(..., description="Message sender (user or assistant)")
    content: str = Field(..., description="Message content")
    timestamp: datetime = Field(..., description="Message timestamp")


# ============================================================================
# WebSocket Models
# ============================================================================

class WSConnectionEvent(BaseModel):
    """WebSocket connection event data."""
    connection_id: str = Field(..., description="Unique connection identifier")
    user_id: str = Field(..., description="Authenticated user identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Connection timestamp")


class TypingIndicator(BaseModel):
    """Typing indicator event for real-time updates."""
    conversation_id: str = Field(..., description="Conversation identifier")
    user_id: str = Field(..., description="User who is typing")
    is_typing: bool = Field(..., description="Typing state (true/false)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")


class WSMessage(BaseModel):
    """WebSocket message envelope."""
    event_type: str = Field(..., description="Event type (message, typing, notification)")
    payload: Dict[str, Any] = Field(..., description="Event payload data")
    conversation_id: Optional[str] = Field(None, description="Target conversation")


# ============================================================================
# Internal Event Models
# ============================================================================

class InternalEvent(BaseModel):
    """Internal event published by backend services."""
    event_type: str = Field(..., description="Event type identifier")
    conversation_id: Optional[str] = Field(None, description="Target conversation")
    user_id: Optional[str] = Field(None, description="Target user")
    payload: Dict[str, Any] = Field(..., description="Event data payload")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    ttl: Optional[int] = Field(None, description="Time-to-live in seconds for cached events")


class TypingStateCache(BaseModel):
    """Cached typing state entry with TTL."""
    conversation_id: str = Field(..., description="Conversation identifier")
    typing_users: List[str] = Field(default_factory=list, description="List of users currently typing")
    expires_at: datetime = Field(..., description="Expiration timestamp for this state")


# ============================================================================
# Health Check Models
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service health status")
    service: str = Field(..., description="Service name")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Check timestamp")
    dependencies: Optional[Dict[str, str]] = Field(None, description="Dependency health status")


# ============================================================================
# Error Models
# ============================================================================

class ErrorResponse(BaseModel):
    """Standardized error response model."""
    error: str = Field(..., description="Error type or code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
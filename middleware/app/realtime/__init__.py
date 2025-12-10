"""
Realtime Package

This package contains WebSocket connection management and event-publishing
functionality for the middleware service.

Modules:
- ws: WebSocket router and connection manager for real-time client communication
- events: Internal event endpoints and TTL-based typing state cache

The realtime package enables:
- Bidirectional WebSocket connections with authenticated clients
- Event broadcasting to specific conversation rooms or users
- Typing indicator management with automatic expiry
- Real-time message delivery notifications
"""

from .events import internal_router, typing_router

__all__ = [
    "internal_router",
    "typing_router",
]
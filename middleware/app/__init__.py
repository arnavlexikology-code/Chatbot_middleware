"""
WebSocket Manager for Real-time Communications
==============================================

Provides WebSocket endpoint for real-time event streaming to mobile clients.

Features:
    - Token-based authentication (query param or Authorization header)
    - Conversation-based subscriptions (multiple clients can subscribe to same conversation)
    - Ping/pong keepalive
    - Graceful disconnect cleanup
    - Thread-safe connection management

Message Types (Client -> Server):
    - {"type": "subscribe", "conversationId": "..."}
    - {"type": "unsubscribe", "conversationId": "..."}
    - {"type": "typing.start", "conversationId": "..."}  # Optional

Events Received (Server -> Client):
    - {"type": "assistant.typing.start", "conversationId": "...", "requestId": "...", "timestamp": "..."}
    - {"type": "assistant.typing.end", "conversationId": "...", "requestId": "...", "timestamp": "..."}
    - {"type": "message", "conversationId": "...", "content": "...", "timestamp": "..."}
"""

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, Set, Optional, Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Header, status
from fastapi.responses import JSONResponse

# Import session verification (to be implemented in auth module)
try:
    from middleware.app.auth.session import verify_session_jwt
except ImportError:
    # Fallback for development
    async def verify_session_jwt(token: str) -> Optional[Dict[str, Any]]:
        """Fallback JWT verification - replace with actual implementation"""
        if token and len(token) > 10:  # Basic validation
            return {"sub": "user@example.com", "email": "user@example.com"}
        return None

logger = logging.getLogger("middleware.realtime.ws")

# Router instance
realtime_router = APIRouter()


class ConnectionManager:
    """
    Manages WebSocket connections and conversation subscriptions.

    Thread-safe manager for handling multiple WebSocket connections
    subscribed to different conversations.

    Attributes:
        active_connections: Dict mapping WebSocket to client metadata
        conversation_rooms: Dict mapping conversationId to Set of WebSockets
        lock: Asyncio lock for thread-safe operations
    """

    def __init__(self):
        # Active WebSocket connections with metadata
        self.active_connections: Dict[WebSocket, Dict[str, Any]] = {}

        # Conversation rooms: conversationId -> Set[WebSocket]
        self.conversation_rooms: Dict[str, Set[WebSocket]] = defaultdict(set)

        # Lock for thread-safe operations
        self.lock = asyncio.Lock()

        logger.info("ConnectionManager initialized")

    async def connect(self, websocket: WebSocket, user_data: Dict[str, Any]) -> None:
        """
        Accept and register a new WebSocket connection.

        Args:
            websocket: WebSocket connection to register
            user_data: User metadata from JWT (email, sub, etc.)
        """
        await websocket.accept()

        async with self.lock:
            self.active_connections[websocket] = {
                "user_data": user_data,
                "subscriptions": set(),
                "connected_at": datetime.utcnow().isoformat()
            }

        logger.info(
            f"WebSocket connected",
            extra={
                "user_email": user_data.get("email"),
                "total_connections": len(self.active_connections)
            }
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Remove a WebSocket connection and clean up subscriptions.

        Args:
            websocket: WebSocket connection to remove
        """
        async with self.lock:
            if websocket in self.active_connections:
                # Get subscriptions before removing
                subscriptions = self.active_connections[websocket].get("subscriptions", set())

                # Remove from all conversation rooms
                for conversation_id in subscriptions:
                    if conversation_id in self.conversation_rooms:
                        self.conversation_rooms[conversation_id].discard(websocket)

                        # Clean up empty rooms
                        if not self.conversation_rooms[conversation_id]:
                            del self.conversation_rooms[conversation_id]

                # Remove connection
                user_data = self.active_connections[websocket].get("user_data", {})
                del self.active_connections[websocket]

                logger.info(
                    f"WebSocket disconnected",
                    extra={
                        "user_email": user_data.get("email"),
                        "subscriptions": list(subscriptions),
                        "total_connections": len(self.active_connections)
                    }
                )

    async def subscribe(self, websocket: WebSocket, conversation_id: str) -> bool:
        """
        Subscribe a WebSocket to a conversation room.

        Args:
            websocket: WebSocket connection
            conversation_id: Conversation ID to subscribe to

        Returns:
            bool: True if subscription successful, False otherwise
        """
        async with self.lock:
            if websocket not in self.active_connections:
                return False

            # Add to conversation room
            self.conversation_rooms[conversation_id].add(websocket)

            # Track subscription in connection metadata
            self.active_connections[websocket]["subscriptions"].add(conversation_id)

            logger.info(
                f"WebSocket subscribed",
                extra={
                    "conversation_id": conversation_id,
                    "user_email": self.active_connections[websocket]["user_data"].get("email"),
                    "room_size": len(self.conversation_rooms[conversation_id])
                }
            )

            return True

    async def unsubscribe(self, websocket: WebSocket, conversation_id: str) -> bool:
        """
        Unsubscribe a WebSocket from a conversation room.

        Args:
            websocket: WebSocket connection
            conversation_id: Conversation ID to unsubscribe from

        Returns:
            bool: True if unsubscription successful, False otherwise
        """
        async with self.lock:
            if websocket not in self.active_connections:
                return False

            # Remove from conversation room
            if conversation_id in self.conversation_rooms:
                self.conversation_rooms[conversation_id].discard(websocket)

                # Clean up empty rooms
                if not self.conversation_rooms[conversation_id]:
                    del self.conversation_rooms[conversation_id]

            # Remove from connection subscriptions
            self.active_connections[websocket]["subscriptions"].discard(conversation_id)

            logger.info(
                f"WebSocket unsubscribed",
                extra={
                    "conversation_id": conversation_id,
                    "user_email": self.active_connections[websocket]["user_data"].get("email")
                }
            )

            return True

    async def broadcast_to_conversation(self, conversation_id: str, event: Dict[str, Any]) -> int:
        """
        Broadcast an event to all WebSockets subscribed to a conversation.

        Args:
            conversation_id: Conversation ID to broadcast to
            event: Event data to send

        Returns:
            int: Number of clients that received the event
        """
        if conversation_id not in self.conversation_rooms:
            logger.debug(f"No subscribers for conversation {conversation_id}")
            return 0

        # Get snapshot of subscribers (to avoid modification during iteration)
        async with self.lock:
            subscribers = list(self.conversation_rooms.get(conversation_id, set()))

        if not subscribers:
            return 0

        # Prepare message
        message = json.dumps(event)
        sent_count = 0
        failed_websockets = []

        # Send to all subscribers
        for websocket in subscribers:
            try:
                await websocket.send_text(message)
                sent_count += 1
            except Exception as e:
                logger.warning(
                    f"Failed to send to WebSocket: {str(e)}",
                    extra={"conversation_id": conversation_id}
                )
                failed_websockets.append(websocket)

        # Clean up failed connections
        for websocket in failed_websockets:
            await self.disconnect(websocket)

        logger.info(
            f"Broadcast event",
            extra={
                "conversation_id": conversation_id,
                "event_type": event.get("type"),
                "recipients": sent_count,
                "failed": len(failed_websockets)
            }
        )

        return sent_count

    async def disconnect_all(self) -> None:
        """
        Disconnect all active WebSocket connections gracefully.

        Used during application shutdown.
        """
        async with self.lock:
            websockets = list(self.active_connections.keys())

        for websocket in websockets:
            try:
                await websocket.close(code=status.WS_1001_GOING_AWAY, reason="Server shutdown")
            except Exception as e:
                logger.warning(f"Error closing WebSocket: {str(e)}")

            await self.disconnect(websocket)

        logger.info("All WebSocket connections closed")


# Global connection manager instance
manager = ConnectionManager()


async def authenticate_websocket(
        websocket: WebSocket,
        token: Optional[str] = Query(None),
        authorization: Optional[str] = Header(None)
) -> Optional[Dict[str, Any]]:
    """
    Authenticate WebSocket connection using token.

    Checks for token in query parameter or Authorization header.

    Args:
        websocket: WebSocket connection
        token: Token from query parameter
        authorization: Authorization header value

    Returns:
        Dict with user data if authenticated, None otherwise
    """
    # Try to get token from query param first, then Authorization header
    auth_token = token

    if not auth_token and authorization:
        # Parse "Bearer <token>" format
        if authorization.startswith("Bearer "):
            auth_token = authorization[7:]
        else:
            auth_token = authorization

    if not auth_token:
        logger.warning("WebSocket connection attempted without token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication required")
        return None

    # Verify JWT
    user_data = await verify_session_jwt(auth_token)

    if not user_data:
        logger.warning("WebSocket connection attempted with invalid token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
        return None

    return user_data


async def handle_ping_pong(websocket: WebSocket) -> None:
    """
    Send periodic ping messages to keep connection alive.

    Args:
        websocket: WebSocket connection to ping
    """
    try:
        while True:
            await asyncio.sleep(30)  # Ping every 30 seconds
            try:
                await websocket.send_json({"type": "ping", "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                # Connection closed
                break
    except asyncio.CancelledError:
        pass


@realtime_router.websocket("/ws")
async def websocket_endpoint(
        websocket: WebSocket,
        token: Optional[str] = Query(None),
        authorization: Optional[str] = Header(None)
):
    """
    WebSocket endpoint for real-time event streaming.

    Authentication:
        - Provide token via query parameter: /realtime/ws?token=YOUR_JWT
        - OR via Authorization header: "Bearer YOUR_JWT"

    Client Messages:
        - {"type": "subscribe", "conversationId": "conv_123"}
        - {"type": "unsubscribe", "conversationId": "conv_123"}
        - {"type": "typing.start", "conversationId": "conv_123"}
        - {"type": "pong", "timestamp": "..."}  # Response to ping

    Server Events:
        - {"type": "connected", "timestamp": "..."}
        - {"type": "subscribed", "conversationId": "..."}
        - {"type": "unsubscribed", "conversationId": "..."}
        - {"type": "ping", "timestamp": "..."}
        - {"type": "assistant.typing.start", "conversationId": "...", ...}
        - {"type": "assistant.typing.end", "conversationId": "...", ...}
        - {"type": "message", "conversationId": "...", ...}
        - {"type": "error", "message": "..."}

    Args:
        websocket: WebSocket connection
        token: Optional JWT token from query parameter
        authorization: Optional Authorization header
    """
    # Authenticate connection
    user_data = await authenticate_websocket(websocket, token, authorization)

    if not user_data:
        return  # Connection already closed by authenticate_websocket

    # Register connection
    await manager.connect(websocket, user_data)

    # Start ping/pong task
    ping_task = asyncio.create_task(handle_ping_pong(websocket))

    try:
        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "user": {
                "email": user_data.get("email"),
                "sub": user_data.get("sub")
            }
        })

        # Handle incoming messages
        while True:
            try:
                # Receive message
                data = await websocket.receive_text()
                message = json.loads(data)

                message_type = message.get("type")
                conversation_id = message.get("conversationId")

                if message_type == "subscribe":
                    if not conversation_id:
                        await websocket.send_json({
                            "type": "error",
                            "message": "conversationId required for subscribe"
                        })
                        continue

                    success = await manager.subscribe(websocket, conversation_id)

                    if success:
                        await websocket.send_json({
                            "type": "subscribed",
                            "conversationId": conversation_id,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    else:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Failed to subscribe"
                        })

                elif message_type == "unsubscribe":
                    if not conversation_id:
                        await websocket.send_json({
                            "type": "error",
                            "message": "conversationId required for unsubscribe"
                        })
                        continue

                    success = await manager.unsubscribe(websocket, conversation_id)

                    if success:
                        await websocket.send_json({
                            "type": "unsubscribed",
                            "conversationId": conversation_id,
                            "timestamp": datetime.utcnow().isoformat()
                        })

                elif message_type == "typing.start":
                    # Client-side typing notification (optional, can be used for multi-user scenarios)
                    logger.debug(f"Client typing.start for conversation {conversation_id}")

                elif message_type == "pong":
                    # Response to ping
                    logger.debug("Received pong from client")

                else:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Unknown message type: {message_type}"
                    })

            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })

            except WebSocketDisconnect:
                logger.info("WebSocket disconnected by client")
                break

            except Exception as e:
                logger.error(f"Error handling WebSocket message: {str(e)}", exc_info=True)
                await websocket.send_json({
                    "type": "error",
                    "message": "Internal error processing message"
                })

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")

    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}", exc_info=True)

    finally:
        # Cancel ping task
        ping_task.cancel()
        try:
            await ping_task
        except asyncio.CancelledError:
            pass

        # Clean up connection
        await manager.disconnect(websocket)


@realtime_router.get("/status")
async def realtime_status():
    """
    Get real-time service status and statistics.

    Returns:
        dict: Connection statistics
    """
    return {
        "status": "ok",
        "active_connections": len(manager.active_connections),
        "active_rooms": len(manager.conversation_rooms),
        "timestamp": datetime.utcnow().isoformat()
    }


# Export manager for use in events.py
__all__ = ["realtime_router", "manager"]
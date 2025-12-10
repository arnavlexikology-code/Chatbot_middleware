"""
CopilotService for Backend Agent

Provides a service for interacting with Copilot Studio and publishing
real-time events to the middleware service.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable, Awaitable
import httpx

from .config import settings

logger = logging.getLogger(__name__)


async def default_event_publisher(event: Dict[str, Any]) -> None:
    """
    Default event publisher that POSTs to middleware /internal/events endpoint.
    
    Args:
        event: Event dictionary with type, conversationId, and other fields
    """
    try:
        url = f"{settings.MIDDLEWARE_BASE_URL}/internal/events"
        headers = {
            "X-Internal-Secret": settings.INTERNAL_SHARED_SECRET,
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=event, headers=headers, timeout=5.0)
            response.raise_for_status()
            logger.debug(f"Published event {event.get('type')} to middleware")
    except Exception as e:
        logger.error(f"Failed to publish event to middleware: {e}", exc_info=True)
        # Don't raise - event publishing failures shouldn't break the main flow


class CopilotService:
    """
    Service for handling Copilot Studio interactions with event publishing.
    
    Simulates streaming by publishing typing events during message processing.
    """
    
    def __init__(
        self,
        event_publisher: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ):
        """
        Initialize CopilotService.
        
        Args:
            event_publisher: Optional async function to publish events.
                           Defaults to default_event_publisher.
        """
        self._event_publisher = event_publisher or default_event_publisher
    
    async def send_message(
        self,
        message: str,
        conversation_id: str,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Simulate sending a message with streaming typing indicators.
        
        Publishes typing.start, optionally typing.progress, and typing.end events.
        
        Args:
            message: User message to process
            conversation_id: Conversation identifier
            request_id: Optional request identifier for tracking
            
        Returns:
            Dict with reply and other response data
        """
        if not request_id:
            request_id = f"req-{datetime.utcnow().timestamp()}"
        
        timestamp = datetime.utcnow().isoformat()
        
        # Publish typing start event
        await self._event_publisher({
            "type": "assistant.typing.start",
            "conversationId": conversation_id,
            "requestId": request_id,
            "timestamp": timestamp
        })
        
        # Simulate processing delay
        await asyncio.sleep(0.1)
        
        # Optionally publish progress events (simulating streaming)
        # For now, we'll skip progress events, but the structure is here
        
        # Simulate generating a response
        await asyncio.sleep(0.2)
        
        # Generate a simulated reply
        reply = f"Simulated reply to: {message}"
        
        # Publish typing end event
        await self._event_publisher({
            "type": "assistant.typing.end",
            "conversationId": conversation_id,
            "requestId": request_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "conversationId": conversation_id,
            "reply": reply,
            "requestId": request_id
        }
    
    async def send_message_with_progress(
        self,
        message: str,
        conversation_id: str,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Simulate sending a message with progress events.
        
        Similar to send_message but includes typing.progress events.
        
        Args:
            message: User message to process
            conversation_id: Conversation identifier
            request_id: Optional request identifier for tracking
            
        Returns:
            Dict with reply and other response data
        """
        if not request_id:
            request_id = f"req-{datetime.utcnow().timestamp()}"
        
        timestamp = datetime.utcnow().isoformat()
        
        # Publish typing start event
        await self._event_publisher({
            "type": "assistant.typing.start",
            "conversationId": conversation_id,
            "requestId": request_id,
            "timestamp": timestamp
        })
        
        # Simulate processing with progress updates
        await asyncio.sleep(0.1)
        
        # Publish progress event
        await self._event_publisher({
            "type": "assistant.typing.progress",
            "conversationId": conversation_id,
            "requestId": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "partialText": "Thinking..."
        })
        
        await asyncio.sleep(0.2)
        
        # Another progress event
        await self._event_publisher({
            "type": "assistant.typing.progress",
            "conversationId": conversation_id,
            "requestId": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "partialText": "Generating response..."
        })
        
        # Generate a simulated reply
        reply = f"Simulated reply to: {message}"
        
        # Publish typing end event
        await self._event_publisher({
            "type": "assistant.typing.end",
            "conversationId": conversation_id,
            "requestId": request_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "conversationId": conversation_id,
            "reply": reply,
            "requestId": request_id
        }


# Global singleton instance
_copilot_service: Optional[CopilotService] = None


def get_copilot_service() -> CopilotService:
    """Get or create Copilot service instance"""
    global _copilot_service
    if _copilot_service is None:
        _copilot_service = CopilotService()
    return _copilot_service


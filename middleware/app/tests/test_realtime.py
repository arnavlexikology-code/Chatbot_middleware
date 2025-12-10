"""
Unit Tests for Realtime Events
===============================

Tests for middleware/app/realtime/events.py

Test Coverage:
--------------
1. POST /internal/events without header => 401
2. POST /internal/events with valid secret => 200
3. POST valid event => returns 200 and GET /realtime/typing returns state for short period
4. After TTL passes, state is absent
5. Typing state cache management (start, progress, end events)

Run tests:
----------
    pytest middleware/app/tests/test_realtime.py -v
    pytest middleware/app/tests/test_realtime.py -v --cov=app.realtime.events
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
import httpx

from app.main import create_application
from app.config import Settings


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    return Settings(
        AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000",
        AZURE_CLIENT_ID="00000000-0000-0000-0000-000000000000",
        AZURE_CLIENT_SECRET="test-secret-1234567890123456789012",
        SESSION_JWT_SECRET="test-jwt-secret-1234567890123456",
        BACKEND_SERVICE_URL="http://backend:8002",
        INTERNAL_SHARED_SECRET="test-internal-secret-1234567890123456",
        ALLOWED_DOMAINS="lithan.com",
        AZURE_REDIRECT_URI="http://localhost:8080/auth/callback"
    )


@pytest.fixture
def app(mock_settings):
    """Create test FastAPI application"""
    with patch("app.realtime.events.get_settings", return_value=mock_settings):
        app = create_application()
        return app


@pytest.fixture
def client(app):
    """Create test client"""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_typing_cache():
    """Reset typing cache before each test"""
    from app.realtime.events import typing_cache
    original_ttl = typing_cache._ttl_seconds
    typing_cache._cache.clear()
    typing_cache._ttl_seconds = 5  # Reset to default
    yield
    typing_cache._cache.clear()
    typing_cache._ttl_seconds = original_ttl


# ============================================================================
# Internal Events Endpoint Tests
# ============================================================================

def test_post_internal_events_without_header_returns_401(client):
    """Test that POST /internal/events without X-Internal-Secret header returns 401"""
    response = client.post(
        "/internal/events",
        json={
            "type": "assistant.typing.start",
            "conversationId": "test-conv-123"
        }
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Unauthorized" in response.json()["detail"]


def test_post_internal_events_with_invalid_secret_returns_401(client, mock_settings):
    """Test that POST /internal/events with invalid secret returns 401"""
    response = client.post(
        "/internal/events",
        headers={"X-Internal-Secret": "wrong-secret"},
        json={
            "type": "assistant.typing.start",
            "conversationId": "test-conv-123"
        }
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Unauthorized" in response.json()["detail"]


def test_post_internal_events_with_valid_secret_returns_200(client, mock_settings):
    """Test that POST /internal/events with valid secret returns 200"""
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        response = client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-123",
                "requestId": "req-123",
                "timestamp": "2024-01-01T00:00:00Z"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "received"
        assert data["event_type"] == "assistant.typing.start"
        assert data["conversation_id"] == "test-conv-123"
        assert "recipients" in data
        
        # Verify publish was called
        mock_manager.publish.assert_called_once()
        call_args = mock_manager.publish.call_args[0][0]
        assert call_args["type"] == "assistant.typing.start"
        assert call_args["conversationId"] == "test-conv-123"


def test_post_typing_start_stores_in_cache(client, mock_settings):
    """Test that POST assistant.typing.start stores state in cache"""
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        response = client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-456",
                "requestId": "req-456",
                "partialText": "Hello"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Query typing state
        typing_response = client.get("/realtime/typing?conversationId=test-conv-456")
        assert typing_response.status_code == status.HTTP_200_OK
        data = typing_response.json()
        
        assert "conversationId" in data
        assert data["conversationId"] == "test-conv-456"
        assert "typingState" in data
        assert data["typingState"]["isTyping"] is True
        assert data["typingState"]["requestId"] == "req-456"
        assert data["typingState"]["partialText"] == "Hello"


def test_post_typing_progress_updates_cache(client, mock_settings):
    """Test that POST assistant.typing.progress updates state in cache"""
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        # Start typing
        client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-789",
                "requestId": "req-789"
            }
        )
        
        # Update with progress
        client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.progress",
                "conversationId": "test-conv-789",
                "requestId": "req-789",
                "partialText": "Hello world"
            }
        )
        
        # Query typing state
        typing_response = client.get("/realtime/typing?conversationId=test-conv-789")
        assert typing_response.status_code == status.HTTP_200_OK
        data = typing_response.json()
        
        assert data["typingState"]["isTyping"] is True
        assert data["typingState"]["partialText"] == "Hello world"


def test_post_typing_end_removes_from_cache(client, mock_settings):
    """Test that POST assistant.typing.end removes state from cache"""
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        # Start typing
        client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-end",
                "requestId": "req-end"
            }
        )
        
        # Verify it's in cache
        typing_response = client.get("/realtime/typing?conversationId=test-conv-end")
        assert typing_response.status_code == status.HTTP_200_OK
        assert typing_response.json() != {}
        
        # End typing
        client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.end",
                "conversationId": "test-conv-end",
                "requestId": "req-end"
            }
        )
        
        # Verify it's removed from cache
        typing_response = client.get("/realtime/typing?conversationId=test-conv-end")
        assert typing_response.status_code == status.HTTP_200_OK
        assert typing_response.json() == {}


# ============================================================================
# Typing State Query Endpoint Tests
# ============================================================================

def test_get_typing_state_without_conversation_id_returns_empty(client):
    """Test that GET /realtime/typing without conversationId returns empty"""
    response = client.get("/realtime/typing")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}


def test_get_typing_state_nonexistent_returns_empty(client):
    """Test that GET /realtime/typing for nonexistent conversation returns empty"""
    response = client.get("/realtime/typing?conversationId=nonexistent")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}


# ============================================================================
# TTL Behavior Tests
# ============================================================================

def test_typing_state_expires_after_ttl(client, mock_settings):
    """Test that typing state expires after TTL (5 seconds)"""
    from app.realtime.events import typing_cache
    
    # Use a shorter TTL for testing (1 second)
    typing_cache._ttl_seconds = 1
    
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        # Start typing
        response = client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-ttl",
                "requestId": "req-ttl"
            }
        )
        assert response.status_code == status.HTTP_200_OK
        
        # Immediately query - should be present
        typing_response = client.get("/realtime/typing?conversationId=test-conv-ttl")
        assert typing_response.status_code == status.HTTP_200_OK
        data = typing_response.json()
        assert data != {}
        assert "typingState" in data
        
        # Wait for TTL to expire (1 second + small buffer)
        time.sleep(1.5)
        
        # Query again - should be expired and return empty
        typing_response = client.get("/realtime/typing?conversationId=test-conv-ttl")
        assert typing_response.status_code == status.HTTP_200_OK
        assert typing_response.json() == {}


def test_typing_state_persists_within_ttl(client, mock_settings):
    """Test that typing state persists within TTL period"""
    from app.realtime.events import typing_cache
    
    # Use a longer TTL for testing (2 seconds)
    typing_cache._ttl_seconds = 2
    
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        # Start typing
        response = client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-persist",
                "requestId": "req-persist"
            }
        )
        assert response.status_code == status.HTTP_200_OK
        
        # Wait less than TTL (0.5 seconds)
        time.sleep(0.5)
        
        # Query - should still be present
        typing_response = client.get("/realtime/typing?conversationId=test-conv-persist")
        assert typing_response.status_code == status.HTTP_200_OK
        data = typing_response.json()
        assert data != {}
        assert "typingState" in data
        assert data["typingState"]["isTyping"] is True


def test_typing_progress_refreshes_ttl(client, mock_settings):
    """Test that typing.progress events refresh the TTL"""
    from app.realtime.events import typing_cache
    
    # Use a short TTL for testing (1 second)
    typing_cache._ttl_seconds = 1
    
    with patch("app.realtime.events.realtime_manager") as mock_manager:
        mock_manager.publish = AsyncMock(return_value=0)
        
        # Start typing
        client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.start",
                "conversationId": "test-conv-refresh",
                "requestId": "req-refresh"
            }
        )
        
        # Wait 0.6 seconds (more than half TTL)
        time.sleep(0.6)
        
        # Send progress event (should refresh TTL)
        client.post(
            "/internal/events",
            headers={"X-Internal-Secret": mock_settings.INTERNAL_SHARED_SECRET},
            json={
                "type": "assistant.typing.progress",
                "conversationId": "test-conv-refresh",
                "requestId": "req-refresh",
                "partialText": "Updated"
            }
        )
        
        # Wait another 0.6 seconds (total 1.2 seconds, but TTL refreshed)
        time.sleep(0.6)
        
        # Query - should still be present because TTL was refreshed
        typing_response = client.get("/realtime/typing?conversationId=test-conv-refresh")
        assert typing_response.status_code == status.HTTP_200_OK
        data = typing_response.json()
        assert data != {}
        assert data["typingState"]["partialText"] == "Updated"


# ============================================================================
# RealtimeManager Publish Tests (WebSocket Integration)
# ============================================================================

@pytest.mark.asyncio
async def test_realtime_manager_publish_broadcasts_to_websocket_clients(mock_settings):
    """
    Test that RealtimeManager.publish() broadcasts events to connected WebSocket clients.
    
    This test demonstrates that:
    1. A WebSocket client can connect and subscribe to a conversation
    2. Publishing an event via RealtimeManager.publish() delivers it to subscribed clients
    3. The event is received as JSON with correct structure
    """
    from app.realtime.ws import realtime_manager
    from app.main import create_application
    
    with patch("app.realtime.ws.verify_session_jwt", new_callable=AsyncMock) as mock_verify:
        # Mock JWT verification to allow WebSocket connection
        mock_verify.return_value = {
            "sub": "test-user",
            "email": "test@example.com"
        }
        
        app = create_application()
        
        # Create test token
        test_token = "test-token-12345678901234567890"
        
        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            # Connect WebSocket
            async with client.websocket_connect(
                f"/realtime/ws?token={test_token}"
            ) as websocket:
                # Receive connection confirmation
                connected_msg = await websocket.receive_json()
                assert connected_msg["type"] == "connected"
                
                # Subscribe to a conversation
                conversation_id = "test-conv-publish-123"
                await websocket.send_json({
                    "type": "subscribe",
                    "conversationId": conversation_id
                })
                
                # Receive subscription confirmation
                subscribed_msg = await websocket.receive_json()
                assert subscribed_msg["type"] == "subscribed"
                assert subscribed_msg["conversationId"] == conversation_id
                
                # Publish an event via RealtimeManager
                test_event = {
                    "type": "message",
                    "conversationId": conversation_id,
                    "content": "Test message from publish",
                    "timestamp": "2024-01-01T00:00:00Z"
                }
                
                recipients = await realtime_manager.publish(test_event)
                
                # Verify at least one recipient (our WebSocket client)
                assert recipients >= 1
                
                # Receive the published event
                received_msg = await websocket.receive_json()
                assert received_msg["type"] == "message"
                assert received_msg["conversationId"] == conversation_id
                assert received_msg["content"] == "Test message from publish"


@pytest.mark.asyncio
async def test_realtime_manager_publish_typing_updates_cache(mock_settings):
    """
    Test that RealtimeManager.publish() updates typing cache for assistant.typing events.
    """
    from app.realtime.ws import realtime_manager
    
    conversation_id = "test-conv-typing-publish"
    
    # Publish typing start event
    typing_start_event = {
        "type": "assistant.typing.start",
        "conversationId": conversation_id,
        "requestId": "req-typing-123",
        "timestamp": "2024-01-01T00:00:00Z",
        "partialText": "Hello"
    }
    
    recipients = await realtime_manager.publish(typing_start_event)
    
    # Verify typing state is stored
    typing_state = await realtime_manager.get_typing_state(conversation_id)
    assert typing_state is not None
    assert typing_state["conversationId"] == conversation_id
    assert typing_state["typingState"]["isTyping"] is True
    assert typing_state["typingState"]["requestId"] == "req-typing-123"
    assert typing_state["typingState"]["partialText"] == "Hello"
    
    # Publish typing end event
    typing_end_event = {
        "type": "assistant.typing.end",
        "conversationId": conversation_id,
        "requestId": "req-typing-123",
        "timestamp": "2024-01-01T00:00:01Z"
    }
    
    await realtime_manager.publish(typing_end_event)
    
    # Verify typing state is removed
    typing_state = await realtime_manager.get_typing_state(conversation_id)
    assert typing_state is None


@pytest.mark.asyncio
async def test_realtime_manager_get_typing_state_returns_none_for_nonexistent(mock_settings):
    """
    Test that get_typing_state() returns None for nonexistent conversations.
    """
    from app.realtime.ws import realtime_manager
    
    typing_state = await realtime_manager.get_typing_state("nonexistent-conv")
    assert typing_state is None

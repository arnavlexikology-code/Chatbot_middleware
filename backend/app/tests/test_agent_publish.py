import importlib
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from fastapi.testclient import TestClient


def get_client(monkeypatch) -> TestClient:
    monkeypatch.setenv("BACKEND_SHARED_SECRET", "supersecret")
    monkeypatch.setenv("MIDDLEWARE_BASE_URL", "http://middleware:8080")
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "internal-secret")
    # Reload settings and app to pick up the new env var for each test.
    config_module = importlib.import_module("backend.app.config")
    importlib.reload(config_module)
    main_module = importlib.import_module("backend.app.main")
    importlib.reload(main_module)
    return TestClient(main_module.app)


def test_agent_chat_rejects_without_secret(monkeypatch):
    client = get_client(monkeypatch)
    response = client.post("/agent/chat")
    assert response.status_code == 401


def test_agent_chat_accepts_with_secret(monkeypatch):
    client = get_client(monkeypatch)
    response = client.post("/agent/chat", headers={"X-Internal-Secret": "supersecret"})
    assert response.status_code == 200
    assert response.json().get("status") == "ok"


def test_agent_health_rejects_without_secret(monkeypatch):
    client = get_client(monkeypatch)
    response = client.get("/agent/health")
    assert response.status_code == 401


def test_agent_health_accepts_with_secret(monkeypatch):
    client = get_client(monkeypatch)
    response = client.get("/agent/health", headers={"X-Internal-Secret": "supersecret"})
    assert response.status_code == 200
    assert response.json().get("status") == "healthy"


def test_publish_typing_rejects_without_secret(monkeypatch):
    client = get_client(monkeypatch)
    response = client.post("/internal/publish-typing")
    assert response.status_code == 401


def test_publish_typing_accepts_with_secret(monkeypatch):
    client = get_client(monkeypatch)
    response = client.post(
        "/internal/publish-typing", headers={"X-Internal-Secret": "supersecret"}
    )
    assert response.status_code == 200
    assert response.json().get("received") is True


@pytest.mark.asyncio
async def test_agent_chat_publishes_typing_events(monkeypatch):
    """
    Test that /agent/chat calls CopilotService which publishes typing.start and typing.end events.
    """
    monkeypatch.setenv("BACKEND_SHARED_SECRET", "supersecret")
    monkeypatch.setenv("MIDDLEWARE_BASE_URL", "http://middleware:8080")
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "internal-secret")
    
    # Reload modules
    config_module = importlib.import_module("backend.app.config")
    importlib.reload(config_module)
    routes_module = importlib.import_module("backend.app.routes")
    importlib.reload(routes_module)
    copilot_service_module = importlib.import_module("backend.app.copilot_service")
    importlib.reload(copilot_service_module)
    
    # Mock httpx.AsyncClient.post
    mock_post = AsyncMock()
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response
    
    with patch("httpx.AsyncClient") as mock_client_class:
        # Mock the context manager behavior
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = mock_post
        mock_client_class.return_value = mock_client
        
        # Get CopilotService and call send_message
        copilot_service = copilot_service_module.get_copilot_service()
        
        result = await copilot_service.send_message(
            message="test message",
            conversation_id="test-conv-123",
            request_id="test-req-456"
        )
        
        # Verify result
        assert result["conversationId"] == "test-conv-123"
        assert result["reply"] is not None
        assert result["requestId"] == "test-req-456"
        
        # Verify that post was called at least twice (typing.start and typing.end)
        assert mock_post.call_count >= 2
        
        # Get all call arguments
        calls = mock_post.call_args_list
        
        # Verify typing.start event was published
        start_call = None
        end_call = None
        for call in calls:
            call_kwargs = call.kwargs
            event = call_kwargs.get("json", {})
            if event.get("type") == "assistant.typing.start":
                start_call = call
            elif event.get("type") == "assistant.typing.end":
                end_call = call
        
        assert start_call is not None, "typing.start event should be published"
        assert end_call is not None, "typing.end event should be published"
        
        # Verify typing.start event structure
        start_event = start_call.kwargs["json"]
        assert start_event["type"] == "assistant.typing.start"
        assert start_event["conversationId"] == "test-conv-123"
        assert start_event["requestId"] == "test-req-456"
        assert "timestamp" in start_event
        
        # Verify typing.end event structure
        end_event = end_call.kwargs["json"]
        assert end_event["type"] == "assistant.typing.end"
        assert end_event["conversationId"] == "test-conv-123"
        assert end_event["requestId"] == "test-req-456"
        assert "timestamp" in end_event
        
        # Verify headers were set correctly
        for call in calls:
            headers = call.kwargs.get("headers", {})
            assert headers.get("X-Internal-Secret") == "internal-secret"
            assert headers.get("Content-Type") == "application/json"


@pytest.mark.asyncio
async def test_agent_chat_endpoint_calls_copilot_service(monkeypatch):
    """
    Test that /agent/chat endpoint calls CopilotService and returns response.
    """
    monkeypatch.setenv("BACKEND_SHARED_SECRET", "supersecret")
    monkeypatch.setenv("MIDDLEWARE_BASE_URL", "http://middleware:8080")
    monkeypatch.setenv("INTERNAL_SHARED_SECRET", "internal-secret")
    
    # Reload modules
    config_module = importlib.import_module("backend.app.config")
    importlib.reload(config_module)
    routes_module = importlib.import_module("backend.app.routes")
    importlib.reload(routes_module)
    main_module = importlib.import_module("backend.app.main")
    importlib.reload(main_module)
    
    # Mock httpx.AsyncClient.post
    mock_post = AsyncMock()
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response
    
    with patch("httpx.AsyncClient") as mock_client_class:
        # Mock the context manager behavior
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = mock_post
        mock_client_class.return_value = mock_client
        
        client = TestClient(main_module.app)
        
        response = client.post(
            "/agent/chat",
            headers={"X-Internal-Secret": "supersecret"},
            json={
                "message": "test message",
                "conversationId": "test-conv-789"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["conversationId"] == "test-conv-789"
        assert "reply" in data
        assert "requestId" in data
        
        # Verify that events were published (at least typing.start and typing.end)
        assert mock_post.call_count >= 2


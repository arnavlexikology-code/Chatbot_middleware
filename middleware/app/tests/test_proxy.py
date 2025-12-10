"""
Unit Tests for Proxy Routes
============================

Tests for middleware/app/proxy/routes.py

Test Coverage:
--------------
1. Authentication enforcement (reject requests without valid JWT)
2. Request validation and sanitization
3. Header stripping (dangerous headers removed)
4. Backend forwarding with correct headers (X-Internal-Secret, user claims)
5. Conversation ID generation when missing
6. Error handling (timeouts, network errors, backend errors)
7. Response pass-through from backend to client

Run tests:
----------
    pytest middleware/tests/test_proxy.py -v
    pytest middleware/tests/test_proxy.py -v --cov=app.proxy
"""

import uuid
from typing import Dict, Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response, TimeoutException, NetworkError

from app.main import create_application
from app.config import Settings


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    return Settings(
        AZURE_TENANT_ID="test-tenant",
        AZURE_CLIENT_ID="test-client",
        AZURE_CLIENT_SECRET="test-secret-1234567890123456789012",
        SESSION_JWT_SECRET="test-jwt-secret-1234567890123456",
        BACKEND_SERVICE_URL="http://backend:8002",
        INTERNAL_SHARED_SECRET="test-internal-secret-1234567890123456",
        ALLOWED_DOMAINS="lithan.com",
        AZURE_REDIRECT_URI="http://localhost:8080/auth/callback"
    )


@pytest.fixture
def mock_backend_client():
    """Create mock backend HTTP client"""
    client = AsyncMock()
    return client


@pytest.fixture
def mock_user_claims():
    """Standard user claims for authenticated requests"""
    return {
        "sub": "user-123",
        "email": "test@lithan.com",
        "name": "Test User",
        "iat": 1234567890,
        "exp": 9999999999
    }


@pytest.fixture
def app(mock_settings, mock_backend_client):
    """Create test FastAPI application"""
    app = create_application()
    
    # Override settings
    app.state.settings = mock_settings
    
    # Mock app state
    mock_app_state = Mock()
    mock_app_state.backend_client = mock_backend_client
    app.state.app_state = mock_app_state
    
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return TestClient(app)


@pytest.fixture(autouse=True)
def patch_get_settings(mock_settings):
    """Automatically patch get_settings in all tests"""
    with patch("app.proxy.routes.get_settings", return_value=mock_settings):
        yield


@pytest.fixture
def auth_headers():
    """Standard authorization headers for authenticated requests"""
    return {
        "Authorization": "Bearer mock-jwt-token-for-testing",
        "Content-Type": "application/json"
    }


# ============================================================================
# Authentication Tests
# ============================================================================

def test_chat_requires_authentication(client):
    """Test that /chat endpoint requires authentication"""
    response = client.post(
        "/chat",
        json={
            "message": "Hello",
            "conversationId": "test-123"
        }
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "authentication token" in response.json()["detail"].lower()


def test_chat_requires_bearer_token_format(client):
    """Test that authorization header must be in Bearer format"""
    response = client.post(
        "/chat",
        headers={"Authorization": "InvalidFormat token123"},
        json={
            "message": "Hello",
            "conversationId": "test-123"
        }
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_agent_status_requires_authentication(client):
    """Test that /agent/status requires authentication"""
    response = client.get("/agent/status")
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================================
# Request Validation Tests
# ============================================================================

def test_chat_validates_empty_message(client, auth_headers):
    """Test that empty messages are rejected"""
    response = client.post(
        "/chat",
        headers=auth_headers,
        json={
            "message": "   ",  # Only whitespace
            "conversationId": "test-123"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_chat_validates_message_too_long(client, auth_headers):
    """Test that messages exceeding max length are rejected"""
    response = client.post(
        "/chat",
        headers=auth_headers,
        json={
            "message": "x" * 5000,  # Exceeds 4000 char limit
            "conversationId": "test-123"
        }
    )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_chat_generates_conversation_id_when_missing(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test that conversation ID is generated when not provided"""
    # Mock backend response
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "conversationId": "generated-uuid",
        "reply": "Hello! How can I help?",
        "timestamp": "2024-01-01T00:00:00Z"
    }
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    # Mock JWT verification
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello"
                # No conversationId provided
            }
        )
    
    assert response.status_code == status.HTTP_200_OK
    
    # Check that backend was called with a generated UUID
    call_args = mock_backend_client.post.call_args
    payload = call_args.kwargs["json"]
    
    # Verify conversation ID is a valid UUID
    conversation_id = payload["conversationId"]
    assert conversation_id is not None
    
    try:
        uuid.UUID(conversation_id)
    except ValueError:
        pytest.fail("Generated conversation ID is not a valid UUID")


# ============================================================================
# Header Security Tests
# ============================================================================

def test_authorization_header_not_forwarded(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims,
    mock_settings
):
    """Test that Authorization header is explicitly not forwarded to backend"""
    # Mock backend response
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "conversationId": "test-123",
        "reply": "Response",
        "timestamp": "2024-01-01T00:00:00Z"
    }
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Test message",
                "conversationId": "test-123"
            }
        )
    
    assert response.status_code == status.HTTP_200_OK
    
    # Verify backend was called
    call_args = mock_backend_client.post.call_args
    backend_headers = call_args.kwargs["headers"]
    
    # Verify Authorization header is NOT forwarded
    assert "Authorization" not in backend_headers
    assert "authorization" not in [k.lower() for k in backend_headers.keys()]
    
    # Verify internal secret header was added
    assert backend_headers["X-Internal-Secret"] == mock_settings.INTERNAL_SHARED_SECRET


def test_internal_secret_header_equals_settings(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims,
    mock_settings
):
    """Test that X-Internal-Secret header equals settings.INTERNAL_SHARED_SECRET"""
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "conversationId": "test-123",
        "reply": "Response",
        "timestamp": "2024-01-01T00:00:00Z"
    }
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Test",
                "conversationId": "test-123"
            }
        )
    
    # Verify internal secret was sent
    call_args = mock_backend_client.post.call_args
    backend_headers = call_args.kwargs["headers"]
    
    assert "X-Internal-Secret" in backend_headers
    assert backend_headers["X-Internal-Secret"] == mock_settings.INTERNAL_SHARED_SECRET


def test_user_claims_forwarded_in_headers(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims,
    mock_settings
):
    """Test that user claims are forwarded to backend in headers"""
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "conversationId": "test-123",
        "reply": "Response",
        "timestamp": "2024-01-01T00:00:00Z"
    }
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Test",
                "conversationId": "test-123"
            }
        )
    
    # Verify user claims were forwarded
    call_args = mock_backend_client.post.call_args
    backend_headers = call_args.kwargs["headers"]
    
    assert backend_headers["X-User-Email"] == mock_user_claims["email"]
    assert backend_headers["X-User-Id"] == mock_user_claims["sub"]
    assert backend_headers["X-User-Name"] == mock_user_claims["name"]


# ============================================================================
# Backend Communication Tests
# ============================================================================

def test_successful_chat_forwarding(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test successful chat message forwarding to backend"""
    # Mock backend response
    backend_response = {
        "conversationId": "test-123",
        "reply": "Hello! I'm the agent. How can I help you today?",
        "metadata": {"intent": "greeting"},
        "timestamp": "2024-01-01T00:00:00Z"
    }
    
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = backend_response
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123",
                "metadata": {"source": "mobile"}
            }
        )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()
    assert response_data["conversationId"] == "test-123"
    assert response_data["reply"] == backend_response["reply"]
    
    # Verify backend was called with correct payload
    call_args = mock_backend_client.post.call_args
    assert call_args.args[0] == "/agent/chat"
    
    payload = call_args.kwargs["json"]
    assert payload["message"] == "Hello"
    assert payload["conversationId"] == "test-123"
    assert payload["metadata"]["source"] == "mobile"
    assert payload["user"]["email"] == mock_user_claims["email"]


def test_backend_timeout_handling(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test handling of backend timeout errors"""
    mock_backend_client.post = AsyncMock(side_effect=TimeoutException("Timeout"))
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123"
            }
        )
    
    assert response.status_code == status.HTTP_504_GATEWAY_TIMEOUT
    assert "timeout" in response.json()["detail"].lower()


def test_backend_network_error_handling(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test handling of backend network errors"""
    mock_backend_client.post = AsyncMock(side_effect=NetworkError("Connection failed"))
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123"
            }
        )
    
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert "backend service" in response.json()["detail"].lower()


def test_backend_401_error_handling(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test handling of backend authentication failure"""
    mock_response = Mock(spec=Response)
    mock_response.status_code = 401
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123"
            }
        )
    
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert "authentication failed" in response.json()["detail"].lower()


def test_backend_rate_limit_handling(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test handling of backend rate limiting"""
    mock_response = Mock(spec=Response)
    mock_response.status_code = 429
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123"
            }
        )
    
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "too many requests" in response.json()["detail"].lower()


def test_backend_500_retries_once_then_raises_502(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test that on backend 500, proxy retries once then raises 502 if still failing"""
    # Mock backend to return 500 on both attempts
    mock_response_500 = Mock(spec=Response)
    mock_response_500.status_code = 500
    
    # Configure mock to return 500 on both calls
    mock_backend_client.post = AsyncMock(return_value=mock_response_500)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123"
            }
        )
    
    # Should raise 502 after retries
    assert response.status_code == status.HTTP_502_BAD_GATEWAY
    assert "unavailable" in response.json()["detail"].lower()
    
    # Verify backend was called twice (initial + 1 retry)
    assert mock_backend_client.post.call_count == 2


def test_backend_500_succeeds_on_retry(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test that retry succeeds if backend recovers"""
    # Mock backend to return 500 first, then 200
    mock_response_500 = Mock(spec=Response)
    mock_response_500.status_code = 500
    
    mock_response_200 = Mock(spec=Response)
    mock_response_200.status_code = 200
    mock_response_200.json.return_value = {
        "conversationId": "test-123",
        "reply": "Success after retry"
    }
    
    # Configure mock to return 500 first, then 200
    mock_backend_client.post = AsyncMock(side_effect=[mock_response_500, mock_response_200])
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Hello",
                "conversationId": "test-123"
            }
        )
    
    # Should succeed after retry
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["reply"] == "Success after retry"
    
    # Verify backend was called twice (initial + 1 retry)
    assert mock_backend_client.post.call_count == 2


# ============================================================================
# Agent Status Endpoint Tests
# ============================================================================

def test_agent_status_success(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test successful agent status check"""
    status_response = {
        "status": "operational",
        "agent": "Test Agent",
        "version": "1.0.0"
    }
    
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = status_response
    mock_backend_client.get = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.get(
            "/agent/status",
            headers=auth_headers
        )
    
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "operational"


def test_agent_status_timeout(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test agent status check timeout handling"""
    mock_backend_client.get = AsyncMock(side_effect=TimeoutException("Timeout"))
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.get(
            "/agent/status",
            headers=auth_headers
        )
    
    assert response.status_code == status.HTTP_504_GATEWAY_TIMEOUT


# ============================================================================
# Payload Validation Tests
# ============================================================================

def test_chat_payload_structure(
    client,
    auth_headers,
    mock_backend_client,
    mock_user_claims
):
    """Test that backend receives correctly structured payload"""
    mock_response = Mock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "conversationId": "test-123",
        "reply": "Response",
        "timestamp": "2024-01-01T00:00:00Z"
    }
    mock_backend_client.post = AsyncMock(return_value=mock_response)
    
    with patch("app.proxy.routes.get_user_claims", return_value=mock_user_claims):
        response = client.post(
            "/chat",
            headers=auth_headers,
            json={
                "message": "Test message",
                "conversationId": "test-123",
                "metadata": {"key": "value"}
            }
        )
    
    # Verify payload structure
    call_args = mock_backend_client.post.call_args
    payload = call_args.kwargs["json"]
    
    assert "message" in payload
    assert "conversationId" in payload
    assert "metadata" in payload
    assert "user" in payload
    
    # Verify user object structure
    assert "email" in payload["user"]
    assert "id" in payload["user"]
    assert "name" in payload["user"]
    
    assert payload["user"]["email"] == mock_user_claims["email"]
    assert payload["user"]["id"] == mock_user_claims["sub"]
"""
Authentication Tests for Middleware Layer

Tests OIDC authentication flow, token exchange, domain validation,
and JWKS signature verification.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta, timezone
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json
from fastapi import HTTPException
from fastapi.testclient import TestClient


# Test RSA key pair generation for mocking JWKS
def generate_test_keys():
    """Generate RSA key pair for testing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()


# Generate test keys once for reuse
TEST_PRIVATE_KEY, TEST_PUBLIC_KEY = generate_test_keys()
TEST_KID = "test-key-id-2024"


def create_mock_id_token(email: str, kid: str = TEST_KID, exp_delta_minutes: int = 60):
    """
    Create a mock ID token signed with test private key.
    
    Args:
        email: User email to include in token
        kid: Key ID for JWKS matching
        exp_delta_minutes: Token expiry in minutes
    
    Returns:
        Encoded JWT string
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "https://login.microsoftonline.com/test-tenant/v2.0",
        "sub": "test-user-sub-123",
        "aud": "test-client-id",
        "exp": now + timedelta(minutes=exp_delta_minutes),
        "iat": now,
        "email": email,
        "name": "Test User",
        "preferred_username": email,
    }
    
    headers = {
        "kid": kid,
        "alg": "RS256"
    }
    
    return jwt.encode(payload, TEST_PRIVATE_KEY, algorithm="RS256", headers=headers)


def create_mock_jwks(kid: str = TEST_KID):
    """
    Create mock JWKS response with public key.
    
    Args:
        kid: Key ID to include in JWKS
    
    Returns:
        JWKS dictionary
    """
    # Convert PEM public key to JWK format
    from jwt.algorithms import RSAAlgorithm
    public_key_obj = serialization.load_pem_public_key(
        TEST_PUBLIC_KEY.encode(),
        backend=default_backend()
    )
    
    jwk = RSAAlgorithm.to_jwk(public_key_obj, as_dict=True)
    jwk['kid'] = kid
    jwk['use'] = 'sig'
    jwk['alg'] = 'RS256'
    
    return {
        "keys": [jwk]
    }


@pytest.fixture
def mock_settings():
    """Mock application settings"""
    settings = Mock()
    settings.ENTRA_TENANT_ID = "test-tenant-id"
    settings.ENTRA_CLIENT_ID = "test-client-id"
    settings.ENTRA_CLIENT_SECRET = "test-client-secret"
    settings.ENTRA_REDIRECT_URI = "http://localhost:8000/auth/callback"
    settings.ALLOWED_EMAIL_DOMAINS = ["lithan.com", "educlaas.com"]
    settings.SESSION_JWT_SECRET = "test-session-secret"
    settings.SESSION_JWT_EXPIRY_MINUTES = 60
    settings.USE_RS256_JWT = False
    return settings


@pytest.fixture
def mock_httpx_client():
    """Mock httpx AsyncClient for token exchange and JWKS"""
    return AsyncMock()


class TestAuthenticationFlow:
    """Test suite for OIDC authentication flow"""
    
    @pytest.mark.asyncio
    async def test_successful_callback_flow(self, mock_settings, mock_httpx_client):
        """
        Test successful OAuth callback:
        - Exchange authorization code for tokens
        - Validate ID token signature via JWKS
        - Check email domain is allowed
        - Return HTML with session token
        """
        # Mock token exchange response
        valid_email = "user@lithan.com"
        id_token = create_mock_id_token(valid_email)
        
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "mock-access-token",
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600
        }
        
        # Mock JWKS endpoint response
        jwks_response = Mock()
        jwks_response.status_code = 200
        jwks_response.json.return_value = create_mock_jwks(TEST_KID)
        
        # Configure mock client to return these responses
        mock_httpx_client.post.return_value = token_response
        mock_httpx_client.get.return_value = jwks_response
        
        # Simulate the callback handler
        with patch('httpx.AsyncClient', return_value=mock_httpx_client):
            from auth import handle_callback  # Adjust import to your actual module
            
            result = await handle_callback(
                code="mock-auth-code",
                state="mock-state",
                settings=mock_settings
            )
            
            # Assertions
            assert result is not None
            assert "session_token" in result or "token" in result
            assert result["email"] == valid_email
            
            # Verify token exchange was called
            mock_httpx_client.post.assert_called_once()
            call_args = mock_httpx_client.post.call_args
            assert "token" in call_args[0][0]  # Token endpoint URL
            
            # Verify JWKS was fetched
            mock_httpx_client.get.assert_called_once()
            jwks_call_args = mock_httpx_client.get.call_args
            assert "keys" in jwks_call_args[0][0] or "discovery" in jwks_call_args[0][0]
    
    
    @pytest.mark.asyncio
    async def test_domain_rejection_returns_403(self, mock_settings, mock_httpx_client):
        """
        Test domain validation:
        - User email is from disallowed domain
        - Should return 403 Forbidden
        - Should return HTML error page
        """
        # Mock token with disallowed domain
        invalid_email = "hacker@evil.com"
        id_token = create_mock_id_token(invalid_email)
        
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "mock-access-token",
            "id_token": id_token,
            "token_type": "Bearer"
        }
        
        jwks_response = Mock()
        jwks_response.status_code = 200
        jwks_response.json.return_value = create_mock_jwks(TEST_KID)
        
        mock_httpx_client.post.return_value = token_response
        mock_httpx_client.get.return_value = jwks_response
        
        with patch('httpx.AsyncClient', return_value=mock_httpx_client):
            from auth import handle_callback
            
            # Should raise HTTPException with 403
            with pytest.raises(HTTPException) as exc_info:
                await handle_callback(
                    code="mock-auth-code",
                    state="mock-state",
                    settings=mock_settings
                )
            
            assert exc_info.value.status_code == 403
            assert "domain" in exc_info.value.detail.lower() or "forbidden" in exc_info.value.detail.lower()
    
    
    @pytest.mark.asyncio
    async def test_jwks_kid_mismatch_raises_error(self, mock_settings, mock_httpx_client):
        """
        Test JWKS signature validation:
        - ID token has kid 'key-123'
        - JWKS only contains kid 'different-key'
        - Should fail signature verification
        """
        valid_email = "user@lithan.com"
        # Create token with specific kid
        id_token = create_mock_id_token(valid_email, kid="key-abc-123")
        
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "mock-access-token",
            "id_token": id_token,
            "token_type": "Bearer"
        }
        
        # JWKS with different kid
        jwks_response = Mock()
        jwks_response.status_code = 200
        jwks_response.json.return_value = create_mock_jwks(kid="different-key-xyz")
        
        mock_httpx_client.post.return_value = token_response
        mock_httpx_client.get.return_value = jwks_response
        
        with patch('httpx.AsyncClient', return_value=mock_httpx_client):
            from auth import handle_callback
            
            # Should raise error due to key mismatch
            with pytest.raises((HTTPException, jwt.exceptions.InvalidTokenError)) as exc_info:
                await handle_callback(
                    code="mock-auth-code",
                    state="mock-state",
                    settings=mock_settings
                )
            
            # Verify it's a signature/key error
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in ["key", "signature", "kid", "unable to find"])
    
    
    @pytest.mark.asyncio
    async def test_expired_id_token_rejected(self, mock_settings, mock_httpx_client):
        """
        Test expired token handling:
        - ID token is expired (exp in the past)
        - Should fail validation
        """
        valid_email = "user@lithan.com"
        # Create expired token (negative exp_delta)
        id_token = create_mock_id_token(valid_email, exp_delta_minutes=-10)
        
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "mock-access-token",
            "id_token": id_token,
            "token_type": "Bearer"
        }
        
        jwks_response = Mock()
        jwks_response.status_code = 200
        jwks_response.json.return_value = create_mock_jwks(TEST_KID)
        
        mock_httpx_client.post.return_value = token_response
        mock_httpx_client.get.return_value = jwks_response
        
        with patch('httpx.AsyncClient', return_value=mock_httpx_client):
            from auth import handle_callback
            
            with pytest.raises((HTTPException, jwt.exceptions.ExpiredSignatureError)) as exc_info:
                await handle_callback(
                    code="mock-auth-code",
                    state="mock-state",
                    settings=mock_settings
                )
            
            error_msg = str(exc_info.value).lower()
            assert "expired" in error_msg or "exp" in error_msg
    
    
    @pytest.mark.asyncio
    async def test_token_exchange_failure(self, mock_settings, mock_httpx_client):
        """
        Test token exchange error handling:
        - Entra ID returns error response
        - Should propagate error appropriately
        """
        # Mock failed token exchange
        token_response = Mock()
        token_response.status_code = 400
        token_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Authorization code expired"
        }
        
        mock_httpx_client.post.return_value = token_response
        
        with patch('httpx.AsyncClient', return_value=mock_httpx_client):
            from auth import handle_callback
            
            with pytest.raises(HTTPException) as exc_info:
                await handle_callback(
                    code="invalid-code",
                    state="mock-state",
                    settings=mock_settings
                )
            
            # Should be 400 or 401
            assert exc_info.value.status_code in [400, 401]
    
    
    @pytest.mark.asyncio
    async def test_missing_email_in_token(self, mock_settings, mock_httpx_client):
        """
        Test handling of ID token without email claim:
        - ID token missing 'email' field
        - Should raise appropriate error
        """
        # Create token without email
        now = datetime.now(timezone.utc)
        payload = {
            "iss": "https://login.microsoftonline.com/test-tenant/v2.0",
            "sub": "test-user-sub-123",
            "aud": "test-client-id",
            "exp": now + timedelta(minutes=60),
            "iat": now,
            # No email claim
            "name": "Test User",
        }
        
        headers = {"kid": TEST_KID, "alg": "RS256"}
        id_token = jwt.encode(payload, TEST_PRIVATE_KEY, algorithm="RS256", headers=headers)
        
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "mock-access-token",
            "id_token": id_token,
            "token_type": "Bearer"
        }
        
        jwks_response = Mock()
        jwks_response.status_code = 200
        jwks_response.json.return_value = create_mock_jwks(TEST_KID)
        
        mock_httpx_client.post.return_value = token_response
        mock_httpx_client.get.return_value = jwks_response
        
        with patch('httpx.AsyncClient', return_value=mock_httpx_client):
            from auth import handle_callback
            
            with pytest.raises(HTTPException) as exc_info:
                await handle_callback(
                    code="mock-auth-code",
                    state="mock-state",
                    settings=mock_settings
                )
            
            error_msg = str(exc_info.value.detail).lower()
            assert "email" in error_msg


class TestDomainValidation:
    """Test suite for email domain validation"""
    
    def test_allowed_domain_passes(self, mock_settings):
        """Test that emails from allowed domains pass validation"""
        from auth import validate_email_domain  # Adjust import
        
        valid_emails = [
            "user@lithan.com",
            "admin@educlaas.com",
            "test.user@lithan.com",
        ]
        
        for email in valid_emails:
            assert validate_email_domain(email, mock_settings.ALLOWED_EMAIL_DOMAINS)
    
    
    def test_disallowed_domain_fails(self, mock_settings):
        """Test that emails from disallowed domains fail validation"""
        from auth import validate_email_domain
        
        invalid_emails = [
            "user@gmail.com",
            "hacker@evil.com",
            "admin@notallowed.com",
        ]
        
        for email in invalid_emails:
            assert not validate_email_domain(email, mock_settings.ALLOWED_EMAIL_DOMAINS)
    
    
    def test_empty_email_fails(self, mock_settings):
        """Test that empty email fails validation"""
        from auth import validate_email_domain
        
        assert not validate_email_domain("", mock_settings.ALLOWED_EMAIL_DOMAINS)
        assert not validate_email_domain(None, mock_settings.ALLOWED_EMAIL_DOMAINS)


class TestHTMLResponses:
    """Test suite for HTML response generation"""
    
    def test_success_html_contains_token(self):
        """Test that success HTML page contains session token"""
        from auth import generate_success_html  # Adjust import
        
        mock_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        html = generate_success_html(mock_token)
        
        assert mock_token in html
        assert "<html" in html.lower()
        assert "success" in html.lower() or "authenticated" in html.lower()
    
    
    def test_error_html_403_domain_rejection(self):
        """Test that 403 error HTML is appropriate for domain rejection"""
        from auth import generate_error_html  # Adjust import
        
        html = generate_error_html(403, "Domain not allowed")
        
        assert "<html" in html.lower()
        assert "403" in html or "forbidden" in html.lower()
        assert "domain" in html.lower()


# Pytest configuration
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
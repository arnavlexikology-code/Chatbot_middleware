"""
Authentication routes for OIDC login and callback handling.

This module implements the OAuth 2.0 / OIDC authorization code flow
with Microsoft Entra ID (Azure AD).
"""

import secrets
import hashlib
import base64
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Query, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import get_settings
from app.auth.utils import (
    verify_id_token,
    extract_email_from_claims,
    validate_email_domain,
    get_user_display_name,
)
from app.auth.session import create_session_jwt_from_id_token


# =============================================================================
# Router Setup
# =============================================================================

auth_router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


# =============================================================================
# PKCE Helper Functions
# =============================================================================

def generate_code_verifier() -> str:
    """
    Generate a cryptographically random code verifier for PKCE.
    
    Returns:
        Base64-URL-encoded random string (43-128 characters)
    """
    verifier_bytes = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(verifier_bytes).decode('utf-8').rstrip('=')


def generate_code_challenge(verifier: str) -> str:
    """
    Generate code challenge from verifier using S256 method.
    
    Args:
        verifier: Code verifier string
        
    Returns:
        Base64-URL-encoded SHA256 hash of verifier
    """
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')


# =============================================================================
# Login Endpoint
# =============================================================================

@auth_router.get("/login", response_class=RedirectResponse)
async def login(request: Request, response: Response):
    """
    Initiate OIDC login flow by redirecting to Microsoft Entra ID.
    
    This endpoint:
    1. Generates secure state and nonce parameters
    2. Optionally generates PKCE challenge (for enhanced security)
    3. Builds authorization URL with all required parameters
    4. Stores state/nonce in session for callback validation
    5. Redirects user to Microsoft login page
    
    Query Parameters:
        None (could add return_url for post-login redirect)
        
    Returns:
        RedirectResponse to Microsoft authorization endpoint
    """
    settings = get_settings()
    
    # Generate security parameters
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    
    # Generate PKCE parameters (optional but recommended)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store state, nonce, and code_verifier in session for callback validation
    # In production, use encrypted session cookies or Redis
    request.session["oauth_state"] = state
    request.session["oauth_nonce"] = nonce
    request.session["code_verifier"] = code_verifier
    
    # Build authorization URL
    auth_endpoint = f"{settings.azure_authority}/oauth2/v2.0/authorize"
    
    params = {
        "client_id": settings.AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.AZURE_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    
    authorization_url = f"{auth_endpoint}?{urlencode(params)}"
    
    return RedirectResponse(url=authorization_url, status_code=302)


# =============================================================================
# Callback Endpoint
# =============================================================================

@auth_router.get("/callback", response_class=HTMLResponse)
async def callback(
    request: Request,
    code: Optional[str] = Query(None, description="Authorization code from Azure AD"),
    state: Optional[str] = Query(None, description="State parameter for CSRF protection"),
    error: Optional[str] = Query(None, description="Error code if authentication failed"),
    error_description: Optional[str] = Query(None, description="Error description"),
):
    """
    Handle OAuth callback from Microsoft Entra ID.
    
    This endpoint:
    1. Validates state parameter against session
    2. Exchanges authorization code for tokens
    3. Verifies ID token signature and claims
    4. Validates user email domain
    5. Creates session JWT
    6. Returns HTML page with deep link for mobile app
    
    Query Parameters:
        code: Authorization code from Azure AD
        state: State parameter (must match session)
        error: Error code if login failed
        error_description: Human-readable error description
        
    Returns:
        HTMLResponse with deep link to mobile app or error page
    """
    settings = get_settings()
    
    # Handle authentication errors from Azure AD
    if error:
        error_msg = error_description or error
        return _render_error_page(
            title="Authentication Failed",
            message=f"Unable to authenticate: {error_msg}",
            show_retry=True
        )
    
    # Validate required parameters
    if not code or not state:
        return _render_error_page(
            title="Invalid Request",
            message="Missing required parameters (code or state)",
            show_retry=True
        )
    
    # Validate state parameter (CSRF protection)
    expected_state = request.session.get("oauth_state")
    if not expected_state or state != expected_state:
        return _render_error_page(
            title="Security Error",
            message="Invalid state parameter. This may be a CSRF attack or expired session.",
            show_retry=True
        )
    
    # Get PKCE verifier from session
    code_verifier = request.session.get("code_verifier")
    nonce = request.session.get("oauth_nonce")
    
    try:
        # Exchange authorization code for tokens
        token_response = await _exchange_code_for_tokens(
            code=code,
            redirect_uri=settings.AZURE_REDIRECT_URI,
            code_verifier=code_verifier,
        )
        
        id_token = token_response.get("id_token")
        if not id_token:
            return _render_error_page(
                title="Authentication Error",
                message="No ID token received from identity provider",
                show_retry=True
            )
        
        # Verify ID token
        try:
            claims = await verify_id_token(id_token)
        except Exception as e:
            return _render_error_page(
                title="Token Verification Failed",
                message=f"Unable to verify identity token: {str(e)}",
                show_retry=True
            )
        
        # Validate nonce if present
        token_nonce = claims.get("nonce")
        if nonce and token_nonce != nonce:
            return _render_error_page(
                title="Security Error",
                message="Nonce mismatch. Please try again.",
                show_retry=True
            )
        
        # Extract email and validate domain
        email = extract_email_from_claims(claims)
        if not email:
            return _render_error_page(
                title="Email Not Found",
                message="Unable to retrieve email address from your account. Please contact support.",
                show_retry=False
            )
        
        # Check if email domain is allowed
        if not validate_email_domain(email, settings.allowed_domains_list):
            allowed_domains_str = ", ".join(settings.allowed_domains_list)
            return _render_error_page(
                title="Access Denied",
                message=f"Your email domain is not authorized. Only users from {allowed_domains_str} can access this application.",
                show_retry=False,
                status_code=403
            )
        
        # Extract user information
        user_name = get_user_display_name(claims)
        user_id = claims.get("sub") or claims.get("oid")
        
        # Create session JWT
        session_token = create_session_jwt_from_id_token(
            id_token_claims=claims,
            email=email,
            additional_claims={
                "authenticated_at": claims.get("iat"),
            }
        )
        
        # Clear session state
        request.session.pop("oauth_state", None)
        request.session.pop("oauth_nonce", None)
        request.session.pop("code_verifier", None)
        
        # Return success page with deep link
        return _render_success_page(
            token=session_token,
            user_name=user_name,
            user_email=email
        )
        
    except httpx.HTTPError as e:
        return _render_error_page(
            title="Network Error",
            message=f"Unable to communicate with authentication service: {str(e)}",
            show_retry=True
        )
    except Exception as e:
        # Log the full error but don't expose details to user
        print(f"Unexpected error in callback: {e}")
        return _render_error_page(
            title="Unexpected Error",
            message="An unexpected error occurred during authentication. Please try again.",
            show_retry=True
        )


# =============================================================================
# Token Exchange Helper
# =============================================================================

async def _exchange_code_for_tokens(
    code: str,
    redirect_uri: str,
    code_verifier: Optional[str] = None,
) -> dict:
    """
    Exchange authorization code for access and ID tokens.
    
    Args:
        code: Authorization code from callback
        redirect_uri: Redirect URI (must match the one used in login)
        code_verifier: PKCE code verifier
        
    Returns:
        Token response dictionary containing id_token, access_token, etc.
        
    Raises:
        httpx.HTTPError: If token exchange fails
        ValueError: If response is invalid
    """
    settings = get_settings()
    
    token_endpoint = f"{settings.azure_authority}/oauth2/v2.0/token"
    
    # Build token request payload
    payload = {
        "client_id": settings.AZURE_CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
    }
    
    # Add client secret if available (confidential client)
    if settings.AZURE_CLIENT_SECRET:
        payload["client_secret"] = settings.AZURE_CLIENT_SECRET
    
    # Add PKCE verifier if used
    if code_verifier:
        payload["code_verifier"] = code_verifier
    
    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0
        )
        
        if not response.is_success:
            error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            error_msg = error_data.get("error_description") or error_data.get("error") or "Token exchange failed"
            raise httpx.HTTPError(f"Token exchange failed: {error_msg}")
        
        token_data = response.json()
        
        if "id_token" not in token_data:
            raise ValueError("Token response missing id_token")
        
        return token_data


# =============================================================================
# HTML Response Templates
# =============================================================================

def _render_success_page(token: str, user_name: str, user_email: str) -> HTMLResponse:
    """
    Render success page with deep link to mobile app.
    
    Args:
        token: Session JWT token
        user_name: User's display name
        user_email: User's email address
        
    Returns:
        HTMLResponse with deep link and fallback instructions
    """
    deep_link = f"myapp://auth-complete?token={token}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Successful</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 12px;
                padding: 40px;
                max-width: 500px;
                width: 100%;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                text-align: center;
            }}
            .success-icon {{
                width: 80px;
                height: 80px;
                background: #10b981;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 24px;
            }}
            .checkmark {{
                width: 40px;
                height: 40px;
                border: 4px solid white;
                border-left: none;
                border-top: none;
                transform: rotate(45deg);
            }}
            h1 {{
                color: #1f2937;
                font-size: 28px;
                margin-bottom: 12px;
            }}
            .welcome {{
                color: #6b7280;
                font-size: 18px;
                margin-bottom: 8px;
            }}
            .email {{
                color: #9ca3af;
                font-size: 14px;
                margin-bottom: 32px;
            }}
            .redirect-message {{
                background: #f3f4f6;
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 24px;
                color: #4b5563;
                font-size: 14px;
            }}
            .button {{
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 14px 32px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 16px;
                transition: background 0.2s;
            }}
            .button:hover {{
                background: #5568d3;
            }}
            .fallback {{
                margin-top: 24px;
                padding-top: 24px;
                border-top: 1px solid #e5e7eb;
                color: #6b7280;
                font-size: 13px;
            }}
            .spinner {{
                width: 20px;
                height: 20px;
                border: 3px solid rgba(102, 126, 234, 0.3);
                border-top-color: #667eea;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
                display: inline-block;
                margin-right: 8px;
            }}
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
        </style>
        <script>
            // Auto-redirect to mobile app
            window.onload = function() {{
                setTimeout(function() {{
                    window.location.href = "{deep_link}";
                }}, 1000);
            }};
        </script>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">
                <div class="checkmark"></div>
            </div>
            
            <h1>Login Successful!</h1>
            <p class="welcome">Welcome, {user_name}</p>
            <p class="email">{user_email}</p>
            
            <div class="redirect-message">
                <div class="spinner"></div>
                Redirecting you to the app...
            </div>
            
            <a href="{deep_link}" class="button">
                Open App
            </a>
            
            <div class="fallback">
                <p>If the app doesn't open automatically, click the button above.</p>
                <p style="margin-top: 8px;">
                    <small>If you're on a desktop, open this page on your mobile device.</small>
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content, status_code=200)


def _render_error_page(
    title: str,
    message: str,
    show_retry: bool = True,
    status_code: int = 400
) -> HTMLResponse:
    """
    Render error page for authentication failures.
    
    Args:
        title: Error title
        message: Error message (no PII)
        show_retry: Whether to show retry button
        status_code: HTTP status code
        
    Returns:
        HTMLResponse with error information
    """
    retry_button = """
        <a href="/auth/login" class="button">
            Try Again
        </a>
    """ if show_retry else ""
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 12px;
                padding: 40px;
                max-width: 500px;
                width: 100%;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                text-align: center;
            }}
            .error-icon {{
                width: 80px;
                height: 80px;
                background: #ef4444;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 24px;
                color: white;
                font-size: 48px;
                font-weight: bold;
            }}
            h1 {{
                color: #1f2937;
                font-size: 24px;
                margin-bottom: 16px;
            }}
            .message {{
                color: #6b7280;
                font-size: 16px;
                line-height: 1.6;
                margin-bottom: 32px;
            }}
            .button {{
                display: inline-block;
                background: #667eea;
                color: white;
                padding: 14px 32px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 16px;
                transition: background 0.2s;
            }}
            .button:hover {{
                background: #5568d3;
            }}
            .support {{
                margin-top: 24px;
                padding-top: 24px;
                border-top: 1px solid #e5e7eb;
                color: #9ca3af;
                font-size: 13px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error-icon">!</div>
            
            <h1>{title}</h1>
            <p class="message">{message}</p>
            
            {retry_button}
            
            <div class="support">
                <p>Need help? Contact your system administrator.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content, status_code=status_code)
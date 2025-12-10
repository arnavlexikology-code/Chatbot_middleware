# Middleware Service

Authentication and proxy middleware for mobile chatbot clients. This service sits between mobile applications and the backend agent gateway, handling OIDC authentication, session management, and request proxying.

## Overview

The middleware service provides:
- **OIDC Authentication**: Microsoft Entra ID (Azure AD) integration for user authentication
- **Session Management**: JWT-based session tokens for authenticated requests
- **Request Proxying**: Secure forwarding of validated requests to the backend service
- **Real-time Communication**: WebSocket support for live chat features
- **Domain-based Access Control**: Email domain whitelisting for authorized users

## Architecture

```
Mobile Apps → Middleware (this service) → Backend → Copilot Studio Agent
```

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Setup Steps

1. **Navigate to the middleware directory:**
   ```bash
   cd middleware
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate

   # Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   
   Create a `.env` file in the `middleware` directory with the following required variables:
   
   ```env
   # Azure AD / Entra ID Configuration
   AZURE_TENANT_ID=your-tenant-id-guid
   AZURE_CLIENT_ID=your-client-id-guid
   AZURE_CLIENT_SECRET=your-client-secret  # Optional for public clients
   AZURE_REDIRECT_URI=https://your-middleware-domain.com/auth/callback

   # Domain-based Access Control
   ALLOWED_DOMAINS=lithan.com,educlaas.com

   # Session JWT Configuration
   SESSION_JWT_SECRET=your-cryptographically-secure-secret-key-min-32-chars
   SESSION_JWT_ALGORITHM=HS256
   SESSION_JWT_EXPIRY_MINUTES=60

   # Backend Service Configuration
   BACKEND_SERVICE_URL=http://localhost:8000
   INTERNAL_SHARED_SECRET=your-shared-secret-for-backend-auth-min-32-chars

   # Middleware Server Configuration
   MIDDLEWARE_HOST=0.0.0.0
   MIDDLEWARE_PORT=8080

   # CORS Configuration (optional)
   ALLOWED_ORIGINS=http://localhost:19006,exp://192.168.1.100:8081

   # JWKS Caching (optional)
   JWKS_CACHE_SECONDS=3600
   ```

   **Important:** 
   - `SESSION_JWT_SECRET` and `INTERNAL_SHARED_SECRET` must be at least 32 characters long
   - Use cryptographically secure random strings for production (e.g., `openssl rand -hex 32`)
   - The `INTERNAL_SHARED_SECRET` must match the value configured in the backend service

5. **Verify configuration:**
   ```bash
   python -m app.config
   ```
   
   This will validate your `.env` configuration and display non-sensitive settings.

## Running the Service

### Development Mode

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

Or using Python directly:
```bash
python -m app.main
```

### Production Mode

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4
```

### With Custom Log Level

```bash
LOG_LEVEL=DEBUG uvicorn app.main:app --reload
```

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest app/tests/test_auth.py
```

## API Endpoints

- **`/health`** - Health check endpoint
- **`/auth/*`** - Authentication routes (OIDC login, callback, token management)
- **`/realtime/*`** - WebSocket connections for live chat
- **`/proxy/*`** - Proxied requests to backend (requires valid JWT)
- **`/docs`** - Interactive API documentation (Swagger UI)
- **`/redoc`** - Alternative API documentation (ReDoc)

## Environment Variables Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AZURE_TENANT_ID` | Azure AD Tenant ID (GUID) | `12345678-1234-1234-1234-123456789abc` |
| `AZURE_CLIENT_ID` | Azure AD Application Client ID (GUID) | `87654321-4321-4321-4321-cba987654321` |
| `AZURE_REDIRECT_URI` | OAuth redirect URI registered in Azure AD | `https://middleware.example.com/auth/callback` |
| `ALLOWED_DOMAINS` | Comma-separated list of allowed email domains | `lithan.com,educlaas.com` |
| `SESSION_JWT_SECRET` | Secret key for signing session JWTs (min 32 chars) | `your-secret-key-here` |
| `BACKEND_SERVICE_URL` | Backend API base URL | `http://localhost:8000` |
| `INTERNAL_SHARED_SECRET` | Shared secret for backend authentication (min 32 chars) | `your-shared-secret-here` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_CLIENT_SECRET` | Azure AD Client Secret (for confidential clients) | `None` |
| `SESSION_JWT_ALGORITHM` | JWT signing algorithm | `HS256` |
| `SESSION_JWT_EXPIRY_MINUTES` | Session JWT expiry time in minutes | `60` |
| `MIDDLEWARE_HOST` | Host to bind the middleware server | `0.0.0.0` |
| `MIDDLEWARE_PORT` | Port to bind the middleware server | `8080` |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `None` |
| `JWKS_CACHE_SECONDS` | Time to cache Azure AD JWKS keys | `3600` |

## Security Considerations

1. **Secrets Management**: Never commit `.env` files or secrets to version control
2. **JWT Secrets**: Use cryptographically secure random strings (minimum 32 characters)
3. **HTTPS**: Always use HTTPS in production for secure token transmission
4. **CORS**: Configure `ALLOWED_ORIGINS` appropriately for your deployment
5. **Domain Validation**: Ensure `ALLOWED_DOMAINS` matches your organization's email domains

## Troubleshooting

### Configuration Validation Errors

Run `python -m app.config` to validate your configuration. Common issues:
- Missing required environment variables
- Invalid GUID formats for Azure IDs
- Secrets shorter than 32 characters
- Invalid domain formats in `ALLOWED_DOMAINS`

### Authentication Issues

- Verify Azure AD app registration matches your configuration
- Check that redirect URI is registered in Azure AD
- Ensure `ALLOWED_DOMAINS` includes the domain of test users
- Verify JWT secret is consistent across service restarts

### Backend Connection Issues

- Verify `BACKEND_SERVICE_URL` is correct and accessible
- Ensure `INTERNAL_SHARED_SECRET` matches the backend configuration
- Check network connectivity and firewall rules

## Development

### Project Structure

```
middleware/
├── app/
│   ├── __init__.py
│   ├── main.py              # Application entry point
│   ├── config.py             # Configuration management
│   ├── models.py             # Pydantic models
│   ├── auth/                 # Authentication module
│   │   ├── routes.py         # Auth endpoints
│   │   ├── session.py        # JWT session management
│   │   └── utils.py          # OIDC token verification
│   ├── proxy/                # Proxy module
│   │   └── routes.py         # Backend proxy endpoints
│   ├── realtime/             # Real-time module
│   │   ├── ws.py             # WebSocket handler
│   │   └── events.py         # Event publishing
│   └── tests/                # Test suite
│       ├── test_auth.py
│       ├── test_proxy.py
│       └── test_realtime.py
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

### Code Style

This project follows PEP 8 style guidelines. Consider using:
- `black` for code formatting
- `flake8` or `pylint` for linting
- `mypy` for type checking

## License

[Add your license information here]


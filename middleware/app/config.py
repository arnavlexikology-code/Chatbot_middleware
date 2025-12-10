"""
Configuration module for the Middleware API Gateway.

This module uses Pydantic Settings to load and validate environment variables
for Azure AD authentication, JWT session management, backend communication,
and CORS settings.

Environment variables are loaded from .env file or system environment.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All configuration for Azure AD (OIDC), JWT sessions, backend communication,
    and security policies are defined here.
    """
    
    # =========================================================================
    # Azure AD / Entra ID Configuration (OIDC Authentication)
    # =========================================================================
    
    AZURE_TENANT_ID: str = Field(
        ...,
        description="Azure AD Tenant ID (GUID format)",
        min_length=36,
        max_length=36,
    )
    
    AZURE_CLIENT_ID: str = Field(
        ...,
        description="Azure AD Application (Client) ID for middleware",
        min_length=36,
        max_length=36,
    )
    
    AZURE_CLIENT_SECRET: Optional[str] = Field(
        None,
        description="Azure AD Client Secret (optional for public clients)",
    )
    
    AZURE_REDIRECT_URI: str = Field(
        ...,
        description="OAuth redirect URI registered in Azure AD (e.g., https://middleware.example.com/auth/callback)",
        min_length=1,
    )
    
    # =========================================================================
    # Domain-based Access Control
    # =========================================================================
    
    ALLOWED_DOMAINS: str = Field(
        ...,
        description="Comma-separated list of allowed email domains (e.g., 'lithan.com,educlaas.com')",
        min_length=1,
    )
    
    # =========================================================================
    # Session JWT Configuration
    # =========================================================================
    
    SESSION_JWT_SECRET: str = Field(
        ...,
        description="Secret key for signing session JWTs (must be cryptographically secure)",
        min_length=32,
    )
    
    SESSION_JWT_ALGORITHM: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256, HS384, or HS512 recommended)",
    )
    
    SESSION_JWT_EXPIRY_MINUTES: int = Field(
        default=60,
        description="Session JWT expiry time in minutes",
        ge=5,
        le=1440,  # Max 24 hours
    )
    
    # =========================================================================
    # Backend Service Configuration
    # =========================================================================
    
    BACKEND_SERVICE_URL: HttpUrl = Field(
        ...,
        description="Backend API base URL (e.g., http://backend:8000)",
    )
    
    INTERNAL_SHARED_SECRET: Optional[str] = Field(
        None,
        description="Shared secret for authenticating backend→middleware requests (if needed)",
        min_length=32,
    )
    
    # =========================================================================
    # Middleware Server Configuration
    # =========================================================================
    
    MIDDLEWARE_HOST: str = Field(
        default="0.0.0.0",
        description="Host to bind the middleware server",
    )
    
    MIDDLEWARE_PORT: int = Field(
        default=8080,
        description="Port to bind the middleware server",
        ge=1,
        le=65535,
    )
    
    # =========================================================================
    # CORS Configuration
    # =========================================================================
    
    ALLOWED_ORIGINS: Optional[str] = Field(
        None,
        description="Comma-separated list of allowed CORS origins (leave empty for no CORS)",
    )
    
    # =========================================================================
    # JWKS Caching Configuration
    # =========================================================================
    
    JWKS_CACHE_SECONDS: int = Field(
        default=3600,
        description="Time to cache Azure AD JWKS keys in seconds",
        ge=300,  # Min 5 minutes
        le=86400,  # Max 24 hours
    )
    
    # =========================================================================
    # Pydantic Settings Configuration
    # =========================================================================
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",  # Ignore extra env vars not defined here
    )
    
    # =========================================================================
    # Computed Properties
    # =========================================================================
    
    @property
    def allowed_domains_list(self) -> List[str]:
        """
        Parse and return ALLOWED_DOMAINS as a clean list.
        
        Returns:
            List of lowercase domain strings without whitespace.
        """
        if not self.ALLOWED_DOMAINS:
            return []
        
        domains = [
            domain.strip().lower()
            for domain in self.ALLOWED_DOMAINS.split(",")
            if domain.strip()
        ]
        return domains
    
    @property
    def allowed_origins_list(self) -> List[str]:
        """
        Parse and return ALLOWED_ORIGINS as a list.
        
        Returns:
            List of allowed origin URLs, or empty list if not configured.
        """
        if not self.ALLOWED_ORIGINS:
            return []
        
        origins = [
            origin.strip()
            for origin in self.ALLOWED_ORIGINS.split(",")
            if origin.strip()
        ]
        return origins
    
    @property
    def azure_authority(self) -> str:
        """
        Construct the Azure AD authority URL.
        
        Returns:
            Full authority URL for OIDC endpoints.
        """
        return f"https://login.microsoftonline.com/{self.AZURE_TENANT_ID}"
    
    @property
    def backend_service_url_str(self) -> str:
        """
        Get backend service URL as string (for HTTP client usage).
        
        Returns:
            Backend URL as string without trailing slash.
        """
        url_str = str(self.BACKEND_SERVICE_URL)
        return url_str.rstrip("/")
    
    # =========================================================================
    # Validators
    # =========================================================================
    
    @field_validator("ALLOWED_DOMAINS")
    @classmethod
    def validate_allowed_domains(cls, v: str) -> str:
        """
        Validate that ALLOWED_DOMAINS contains at least one valid domain.
        
        Args:
            v: Raw comma-separated domains string
            
        Returns:
            Validated domains string
            
        Raises:
            ValueError: If no valid domains are provided
        """
        domains = [d.strip() for d in v.split(",") if d.strip()]
        
        if not domains:
            raise ValueError("ALLOWED_DOMAINS must contain at least one domain")
        
        for domain in domains:
            if not domain or "." not in domain:
                raise ValueError(
                    f"Invalid domain format: '{domain}'. "
                    "Expected format: 'example.com'"
                )
            
            # Basic validation: domain should not contain spaces or special chars
            if " " in domain or "@" in domain:
                raise ValueError(
                    f"Invalid domain format: '{domain}'. "
                    "Domain should not contain spaces or @ symbols"
                )
        
        return v
    
    @field_validator("SESSION_JWT_ALGORITHM")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """
        Validate JWT algorithm is one of the supported HMAC algorithms.
        
        Args:
            v: JWT algorithm string
            
        Returns:
            Validated algorithm string
            
        Raises:
            ValueError: If algorithm is not supported
        """
        allowed_algorithms = ["HS256", "HS384", "HS512"]
        
        if v not in allowed_algorithms:
            raise ValueError(
                f"JWT algorithm must be one of {allowed_algorithms}, got: {v}"
            )
        
        return v
    
    @field_validator("AZURE_TENANT_ID", "AZURE_CLIENT_ID")
    @classmethod
    def validate_guid_format(cls, v: str) -> str:
        """
        Validate that Azure IDs are in GUID format.
        
        Args:
            v: GUID string
            
        Returns:
            Validated GUID string
            
        Raises:
            ValueError: If not a valid GUID format
        """
        import re
        
        guid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE
        )
        
        if not guid_pattern.match(v):
            raise ValueError(
                f"Invalid GUID format: {v}. "
                "Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            )
        
        return v.lower()


# =============================================================================
# Settings Singleton
# =============================================================================

@lru_cache()
def get_settings() -> Settings:
    """
    Get or create a singleton Settings instance.
    
    This function is cached so that the settings are loaded only once
    during the application lifecycle. The cache is thread-safe.
    
    Returns:
        Settings instance with all configuration loaded and validated.
        
    Raises:
        ValidationError: If required environment variables are missing
                        or invalid.
    
    Example:
        >>> from app.config import get_settings
        >>> settings = get_settings()
        >>> print(settings.AZURE_TENANT_ID)
    """
    return Settings()


# Export settings instance for convenience
settings = get_settings()


# =============================================================================
# Configuration Helpers
# =============================================================================

def is_domain_allowed(email: str) -> bool:
    """
    Check if an email address belongs to an allowed domain.
    
    Args:
        email: Email address to check
        
    Returns:
        True if email domain is in ALLOWED_DOMAINS, False otherwise.
        
    Example:
        >>> is_domain_allowed("user@lithan.com")
        True
        >>> is_domain_allowed("user@external.com")
        False
    """
    if not email or "@" not in email:
        return False
    
    domain = email.split("@")[-1].lower().strip()
    return domain in settings.allowed_domains_list


def validate_configuration() -> dict:
    """
    Validate critical configuration settings and return a status report.
    
    This can be called during application startup to ensure all required
    configuration is present and valid.
    
    Returns:
        Dictionary with validation status and any warnings.
        
    Example:
        >>> status = validate_configuration()
        >>> if not status["valid"]:
        ...     print(status["errors"])
    """
    errors = []
    warnings = []
    
    # Check critical secrets
    if len(settings.SESSION_JWT_SECRET) < 32:
        errors.append("SESSION_JWT_SECRET is too short (minimum 32 characters)")
    
    if settings.INTERNAL_SHARED_SECRET and len(settings.INTERNAL_SHARED_SECRET) < 32:
        warnings.append("INTERNAL_SHARED_SECRET is shorter than recommended (32+ chars)")
    
    # Check Azure AD configuration
    if not settings.AZURE_CLIENT_SECRET:
        warnings.append("AZURE_CLIENT_SECRET is not set (required for confidential clients)")
    
    # Check allowed domains
    if not settings.allowed_domains_list:
        errors.append("No allowed domains configured")
    
    # Check backend URL
    if "localhost" in settings.backend_service_url_str or "127.0.0.1" in settings.backend_service_url_str:
        warnings.append("Backend URL points to localhost (may cause issues in containers)")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "allowed_domains": settings.allowed_domains_list,
        "jwt_expiry_minutes": settings.SESSION_JWT_EXPIRY_MINUTES,
    }


# =============================================================================
# Example Usage & Documentation
# =============================================================================

if __name__ == "__main__":
    """
    Example usage and configuration validation.
    
    Run this module directly to validate your .env configuration:
        python -m app.config
    """
    import json
    
    print("=" * 80)
    print("MIDDLEWARE CONFIGURATION")
    print("=" * 80)
    
    try:
        config = get_settings()
        
        print("\n✓ Configuration loaded successfully!\n")
        
        # Display non-sensitive configuration
        print("Azure AD Configuration:")
        print(f"  Tenant ID:      {config.AZURE_TENANT_ID}")
        print(f"  Client ID:      {config.AZURE_CLIENT_ID}")
        print(f"  Authority URL:  {config.azure_authority}")
        print(f"  Redirect URI:   {config.AZURE_REDIRECT_URI}")
        
        print("\nAccess Control:")
        print(f"  Allowed Domains: {', '.join(config.allowed_domains_list)}")
        
        print("\nSession Management:")
        print(f"  JWT Algorithm:  {config.SESSION_JWT_ALGORITHM}")
        print(f"  JWT Expiry:     {config.SESSION_JWT_EXPIRY_MINUTES} minutes")
        print(f"  JWKS Cache:     {config.JWKS_CACHE_SECONDS} seconds")
        
        print("\nBackend Configuration:")
        print(f"  Backend URL:    {config.backend_service_url_str}")
        
        print("\nServer Configuration:")
        print(f"  Host:           {config.MIDDLEWARE_HOST}")
        print(f"  Port:           {config.MIDDLEWARE_PORT}")
        
        if config.allowed_origins_list:
            print("\nCORS Configuration:")
            print(f"  Allowed Origins: {', '.join(config.allowed_origins_list)}")
        
        # Run validation
        print("\n" + "=" * 80)
        print("CONFIGURATION VALIDATION")
        print("=" * 80 + "\n")
        
        status = validate_configuration()
        
        if status["valid"]:
            print("✓ All critical checks passed!")
        else:
            print("✗ Configuration errors found:")
            for error in status["errors"]:
                print(f"  - {error}")
        
        if status["warnings"]:
            print("\n⚠ Warnings:")
            for warning in status["warnings"]:
                print(f"  - {warning}")
        
        print("\n" + "=" * 80)
        
    except Exception as e:
        print(f"\n✗ Configuration error: {e}")
        print("\nPlease ensure your .env file contains all required variables:")
        print("""
Required variables:
  - AZURE_TENANT_ID
  - AZURE_CLIENT_ID
  - AZURE_REDIRECT_URI
  - ALLOWED_DOMAINS
  - SESSION_JWT_SECRET
  - BACKEND_SERVICE_URL

Optional variables:
  - AZURE_CLIENT_SECRET
  - INTERNAL_SHARED_SECRET
  - ALLOWED_ORIGINS
  - MIDDLEWARE_HOST (default: 0.0.0.0)
  - MIDDLEWARE_PORT (default: 8080)
  - SESSION_JWT_ALGORITHM (default: HS256)
  - SESSION_JWT_EXPIRY_MINUTES (default: 60)
  - JWKS_CACHE_SECONDS (default: 3600)
        """)
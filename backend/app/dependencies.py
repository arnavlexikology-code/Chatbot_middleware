from fastapi import Header, HTTPException, status

from .config import settings


def verify_internal_secret(x_internal_secret: str | None = Header(None)) -> str:
    """
    Dependency that ensures requests include the expected internal secret.
    """
    expected = getattr(settings, "INTERNAL_SHARED_SECRET", None)
    if not expected:
        # fail fast and log configuration problem
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: INTERNAL_SHARED_SECRET not set"
        )
    if not x_internal_secret or x_internal_secret != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal secret")
    return x_internal_secret



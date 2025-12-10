from fastapi import Header, HTTPException

from .config import settings


def verify_internal_secret(x_internal_secret: str | None = Header(None)) -> str:
    """
    Dependency that ensures requests include the expected internal secret.
    """
    if not x_internal_secret or x_internal_secret != settings.BACKEND_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return x_internal_secret



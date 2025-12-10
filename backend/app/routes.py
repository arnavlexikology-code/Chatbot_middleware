from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional

from .dependencies import verify_internal_secret
from .copilot_service import get_copilot_service

# Routes intended for agent interactions
agent_router = APIRouter(
    prefix="/agent", dependencies=[Depends(verify_internal_secret)]
)


@agent_router.post("/chat")
async def agent_chat(payload: dict):
    """
    Chat entry point for the agent.
    
    Calls CopilotService to process the message and publish typing events.
    
    Expected payload:
        - message: str (user message)
        - conversationId: str (conversation identifier)
        - requestId: Optional[str] (request identifier, auto-generated if not provided)
    """
    conversation_id = payload.get("conversationId")
    if not conversation_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="conversationId is required"
        )
    
    message = payload.get("message", "")
    request_id = payload.get("requestId")
    
    # Get CopilotService instance
    copilot_service = get_copilot_service()
    
    # Send message (this will publish typing events)
    result = await copilot_service.send_message(
        message=message,
        conversation_id=conversation_id,
        request_id=request_id
    )
    
    return {
        "conversationId": result["conversationId"],
        "reply": result["reply"],
        "requestId": result["requestId"],
        "status": "ok"
    }


@agent_router.get("/health")
async def agent_health():
    return {"status": "healthy"}


# Internal-only routes
internal_router = APIRouter(
    prefix="/internal", dependencies=[Depends(verify_internal_secret)]
)


@internal_router.post("/publish-typing")
async def publish_typing():
    # Stub handler for internal typing events
    return {"received": True}

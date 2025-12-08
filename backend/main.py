from typing import Optional, Dict, Any, List
import datetime
import json
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import Copilot service
from copilot_service import get_copilot_service

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# SETTINGS
# -------------------------------------------------------------------

MAX_MESSAGE_LENGTH = 1500   # Maximum characters allowed per user message


# -------------------------------------------------------------------
# MODELS
# -------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str


class LearningModule(BaseModel):
    title: str
    description: str
    dailyPlan: List[str] = Field(default_factory=list)


class LearningPlan(BaseModel):
    topic: str
    level: str
    durationWeeks: int
    modules: List[LearningModule]
    youtubeLinks: List[str]
    linkedinLinks: List[str]


class ChatResponse(BaseModel):
    reply: str
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.utcnow()
        .replace(microsecond=0)
        .isoformat() + "Z"
    )
    agent_activity: Optional[Dict[str, Any]] = None
    learning_plan: Optional[LearningPlan] = None


# -------------------------------------------------------------------
# LOAD: KNOWLEDGE BASE
# -------------------------------------------------------------------

KB_PATH = Path(__file__).parent / "knowledge_base.json"
KB: Dict[str, Any] = {}

if KB_PATH.exists():
    raw = json.loads(KB_PATH.read_text(encoding="utf-8"))

    # Support the structure you showed:
    # {
    #   "id": "...",
    #   "type": "message",
    #   ...
    #   "channelData": {
    #       "responseType": "knowledgeBase",
    #       "knowledgeBase": { ... }
    #   }
    # }
    kb_section = raw.get("channelData", {}).get("knowledgeBase")

    # Fallback: if in the future you store the KB as a plain object,
    # this will still work:
    if kb_section is None and "knowledgeBase" in raw:
        kb_section = raw.get("knowledgeBase")

    KB = kb_section or {}
else:
    print("⚠️ WARNING: knowledge_base.json not found — learning mode will be limited.")


# -------------------------------------------------------------------
# Build Learning Plan from Knowledge Base
# -------------------------------------------------------------------

def build_learning_plan(user_message: str) -> Optional[LearningPlan]:
    text = user_message.lower()

    matched_key: Optional[str] = None
    for key in KB.keys():
        if key.lower() in text:
            matched_key = key
            break

    if not matched_key:
        return None

    data = KB[matched_key]

    return LearningPlan(
        topic=data.get("topic", matched_key.capitalize()),
        level=data.get("level", "Beginner"),
        durationWeeks=data.get("durationWeeks", len(data.get("modules", []))),
        modules=[
            LearningModule(
                title=mod.get("title", "Untitled"),
                description=mod.get("description", ""),
                dailyPlan=mod.get("dailyPlan", []),
            )
            for mod in data.get("modules", [])
        ],
        youtubeLinks=data.get("youtubeLinks", []),
        linkedinLinks=data.get("linkedinLinks", []),
    )


# -------------------------------------------------------------------
# Build MS-Agent-Compatible Activity JSON (Adaptive Card)
# -------------------------------------------------------------------

def build_agent_activity(plan: LearningPlan) -> Dict[str, Any]:
    """
    Builds a Bot Framework-compatible Activity object using
    an Adaptive Card attachment instead of custom channelData responseType.
    """

    # Build module blocks (title + description, compact)
    module_items: List[Dict[str, Any]] = []
    for module in plan.modules:
        module_items.append(
            {
                "type": "TextBlock",
                "text": f"{module.title}\n- {module.description}",
                "wrap": True,
            }
        )

    # Build links markdown
    youtube_text = ""
    if plan.youtubeLinks:
        youtube_lines = [f"- {url}" for url in plan.youtubeLinks]
        youtube_text = "\n".join(youtube_lines)

    linkedin_text = ""
    if plan.linkedinLinks:
        linkedin_lines = [f"- {url}" for url in plan.linkedinLinks]
        linkedin_text = "\n".join(linkedin_lines)

    # Adaptive Card content (generic for any topic)
    card_content: Dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        "body": [
            {
                "type": "TextBlock",
                "text": f"{plan.topic} – Learning Curriculum",
                "weight": "Bolder",
                "size": "Large",
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": f"Level: {plan.level}, Duration: {plan.durationWeeks} weeks",
                "wrap": True,
            },
            {
                "type": "TextBlock",
                "text": "Modules:",
                "weight": "Bolder",
                "spacing": "Medium",
            },
            {
                "type": "Container",
                "items": module_items,
                "spacing": "Small",
            },
        ],
    }

    # Add YouTube links if available
    if youtube_text:
        card_content["body"].extend(
            [
                {
                    "type": "TextBlock",
                    "text": "YouTube Links:",
                    "weight": "Bolder",
                    "spacing": "Medium",
                },
                {
                    "type": "TextBlock",
                    "text": youtube_text,
                    "wrap": True,
                },
            ]
        )

    # Add LinkedIn links if available
    if linkedin_text:
        card_content["body"].extend(
            [
                {
                    "type": "TextBlock",
                    "text": "LinkedIn Learning Paths:",
                    "weight": "Bolder",
                    "spacing": "Medium",
                },
                {
                    "type": "TextBlock",
                    "text": linkedin_text,
                    "wrap": True,
                },
            ]
        )

    # Full Activity object
    return {
        "id": f"activity-{plan.topic.lower().replace(' ', '-')}",
        "type": "message",
        "timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "serviceUrl": "https://example.contoso.com",
        "channelId": "webchat",
        "conversation": {
            "id": "conv-learning-response"
        },
        "from": {
            "id": "agent-learning",
            "name": "Learning Assistant",
            "role": "bot"
        },
        "recipient": {
            "id": "user-request",
            "name": "User",
            "role": "user"
        },
        "replyToId": "incoming-activity-id",
        "locale": "en-US",
        "text": f"Here is a {plan.level} learning plan for {plan.topic}.",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card_content,
            }
        ],
    }


# -------------------------------------------------------------------
# Chat Logic
# -------------------------------------------------------------------

def generate_reply(user_message: str) -> ChatResponse:

    # Length check
    if len(user_message) > MAX_MESSAGE_LENGTH:
        return ChatResponse(
            reply=(
                f"⚠️ Your message is too long ({len(user_message)} characters). "
                f"Maximum allowed: {MAX_MESSAGE_LENGTH}. "
                "Please shorten your message and try again."
            )
        )

    text = user_message.lower().strip()

    # Learning Mode
    learning_keywords = ["learn", "learning", "study", "course", "curriculum"]
    if any(k in text for k in learning_keywords):
        plan = build_learning_plan(text)
        if plan:

            agent_activity = build_agent_activity(plan)

            return ChatResponse(
                reply=(
                    f"Hi! 👋 Here is a {plan.level} learning curriculum for {plan.topic}. "
                    "I've also included YouTube and LinkedIn Learning videos."
                ),
                learning_plan=plan,
                agent_activity=agent_activity
            )
        else:
            return ChatResponse(
                reply=(
                    "I can help you with your learning curriculum. "
                    "Try topics from my knowledge base: Python, React, etc. "
                    "You may also add new topics in knowledge_base.json 🙂."
                )
            )

    # Greeting
    if any(word in text for word in ["hello", "hi", "hey", "mingalaba"]):
        return ChatResponse(
            reply=(
                "Hi! 👋 I'm your learning chatbot. I can help you generate curated "
                "learning plans with YouTube and LinkedIn Learning videos."
            )
        )

    # Time / Name / Help
    if "time" in text:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return ChatResponse(reply=f"The current server time is {now}.")

    if "your name" in text or "who are you" in text:
        return ChatResponse(
            reply=(
                "I'm a learning chatbot. I generate curated learning curriculums "
                "with YouTube and LinkedIn Learning videos."
            )
        )

    if "help" in text:
        return ChatResponse(
            reply=(
                "You can ask me things like:\n"
                "- 'I want to learn Python'\n"
                "- 'Teach me React'\n"
                "- 'Create a learning curriculum for Java'\n"
            )
        )

    # Default echo
    return ChatResponse(
        reply=(
            f"You said: '{user_message}'. "
            "If this is about learning, try something like: 'I want to learn Python'."
        )
    )


# -------------------------------------------------------------------
# ENDPOINTS
# -------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "mode": "copilot-studio-integration"}


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(payload: ChatRequest):
    """
    Chat endpoint - now powered by Copilot Studio
    """
    try:
        logger.info(f"Received message: {payload.message}")
        
        # Get Copilot service
        copilot_service = get_copilot_service()
        
        # Send message to Copilot Studio (empty message gets greeting)
        response_data = await copilot_service.send_message(payload.message)
        
        # Build agent activity if there are attachments
        agent_activity = None
        if response_data.get("has_attachments"):
            agent_activity = {
                "id": f"activity-{datetime.datetime.utcnow().timestamp()}",
                "type": "message",
                "text": response_data["reply"],
                "attachments": response_data["attachments"]
            }
        
        return ChatResponse(
            reply=response_data["reply"],
            agent_activity=agent_activity
        )
        
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/copilot/status")
async def copilot_status():
    """Check Copilot Studio connection status"""
    try:
        copilot_service = get_copilot_service()
        return {
            "connected": copilot_service._is_initialized,
            "conversation_id": copilot_service._conversation_id
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}
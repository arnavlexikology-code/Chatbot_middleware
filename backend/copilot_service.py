import os
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv
from msal import PublicClientApplication
from microsoft_agents.activity import ActivityTypes
from microsoft_agents.copilotstudio.client import ConnectionSettings, CopilotClient, PowerPlatformCloud, AgentType
from local_token_cache import LocalTokenCache

load_dotenv()

logger = logging.getLogger(__name__)
TOKEN_CACHE = LocalTokenCache("./.local_token_cache.json")


class CopilotService:
    def __init__(self):
        self._client = None
        self._conversation_id = None
        self._is_initialized = False

    def _acquire_token(self, app_client_id: str, tenant_id: str) -> str:
        """Acquire token from Azure AD"""
        pca = PublicClientApplication(
            client_id=app_client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            token_cache=TOKEN_CACHE,
        )

        token_request = {
            "scopes": ["https://api.powerplatform.com/.default"],
        }
        
        accounts = pca.get_accounts()
        token = None
        
        try:
            if accounts:
                logger.info("Attempting silent token acquisition...")
                response = pca.acquire_token_silent(
                    token_request["scopes"], account=accounts[0]
                )
                token = response.get("access_token")
                
                if not token:
                    logger.warning("Silent acquisition failed, trying interactive...")
                    response = pca.acquire_token_interactive(**token_request)
                    token = response.get("access_token")
            else:
                logger.info("No cached accounts, using interactive login...")
                response = pca.acquire_token_interactive(**token_request)
                token = response.get("access_token")
                
        except Exception as e:
            logger.error(f"Error acquiring token: {e}")
            raise Exception(f"Failed to acquire authentication token: {e}")

        if not token:
            raise Exception("Failed to acquire access token")
            
        return token

    def _initialize_client(self):
        """Initialize Copilot Studio client"""
        if self._is_initialized:
            return

        logger.info("Initializing Copilot Studio client...")
        
        settings = ConnectionSettings(
            environment_id=os.environ.get("COPILOTSTUDIOAGENT__ENVIRONMENTID"),
            agent_identifier=os.environ.get("COPILOTSTUDIOAGENT__SCHEMANAME"),
            cloud=PowerPlatformCloud.PROD,  
            copilot_agent_type=AgentType.PUBLISHED,  
            custom_power_platform_cloud=None  
        )
        
        token = self._acquire_token(
            app_client_id=os.environ.get("COPILOTSTUDIOAGENT__AGENTAPPID"),
            tenant_id=os.environ.get("COPILOTSTUDIOAGENT__TENANTID"),
        )
        
        self._client = CopilotClient(settings, token)
        
        self._is_initialized = True

    async def _start_conversation(self):
        """Start conversation and get conversation ID and greeting message"""
        logger.info("Starting conversation with Copilot Studio...")
        activities = self._client.start_conversation(True)
        
        greeting_message = None
        
        # Get conversation ID and greeting from activities
        async for activity in activities:
            if activity and hasattr(activity, 'conversation') and activity.conversation:
                self._conversation_id = activity.conversation.id
                logger.info(f"Conversation started: {self._conversation_id}")
                
                # Capture greeting message if it exists
                if hasattr(activity, 'text') and activity.text:
                    greeting_message = activity.text
                    logger.info(f"Greeting message: {greeting_message}")
            else:
                logger.warning(f"Received null/invalid activity: {activity}")
        
        if not self._conversation_id:
            raise ValueError("Failed to get conversation ID from Copilot Studio")
        
        return greeting_message

    async def send_message(self, message: str) -> Dict[str, Any]:
        """Send message to Copilot Studio and get response"""
        try:
            # Initialize client if needed
            greeting_message = None
            if not self._is_initialized:
                self._initialize_client()
                greeting_message = await self._start_conversation()
            
            # If this is a request for intro (empty message), return greeting
            if not message.strip() and greeting_message:
                return {
                    "reply": greeting_message,
                    "all_responses": [greeting_message],
                    "conversation_id": self._conversation_id,
                    "has_attachments": False,
                    "attachments": []
                }

            logger.info(f"Sending message: {message}")
            
            # Send message to Copilot Studio
            replies = self._client.ask_question(message, self._conversation_id)
            
            responses = []
            text_response = ""
            attachments = []
            
            # Process all replies
            async for reply in replies:
                if reply.type == ActivityTypes.message:
                    if reply.text:
                        text_response = reply.text
                        responses.append(reply.text)
                    
                    # Check for attachments (Adaptive Cards)
                    if hasattr(reply, 'attachments') and reply.attachments:
                        for attachment in reply.attachments:
                            attachments.append({
                                "contentType": attachment.content_type,
                                "content": attachment.content
                            })
                    
                    # Check for suggested actions
                    if hasattr(reply, 'suggested_actions') and reply.suggested_actions:
                        logger.info(f"Suggested actions: {reply.suggested_actions}")
                
                elif reply.type == ActivityTypes.end_of_conversation:
                    logger.info("End of conversation received")
                    break

            return {
                "reply": text_response or " ".join(responses) or "No response from Copilot Studio",
                "attachments": attachments,
                "has_attachments": len(attachments) > 0
            }
            
        except Exception as e:
            logger.error(f"Error sending message to Copilot Studio: {e}")
            raise Exception(f"Failed to communicate with Copilot Studio: {e}")


# Global singleton instance
_copilot_service = None


def get_copilot_service() -> CopilotService:
    """Get or create Copilot service instance"""
    global _copilot_service
    if _copilot_service is None:
        _copilot_service = CopilotService()
    return _copilot_service

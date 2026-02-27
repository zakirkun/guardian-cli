"""
OpenAI Provider Implementation
OpenAI GPT models via OpenAI API
"""

import os
from typing import Optional, Dict, Any, List, Union

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from ai.providers.base_provider import BaseProvider


class OpenAIProvider(BaseProvider):
    """OpenAI API provider"""
    
    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        
        # Get OpenAI-specific configuration
        ai_config = config.get("ai", {})
        openai_config = ai_config.get("openai", {})
        
        self.model_name = openai_config.get("model", "gpt-4-turbo")
        # Prefer config file over environment variable
        self.api_key = openai_config.get("api_key") or os.environ.get("OPENAI_API_KEY")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)
        
        self.backend = None
        self._initialize()
    
    def _initialize(self):
        """Initialize OpenAI backend"""
        if not LANGCHAIN_AVAILABLE:
            raise RuntimeError(
                "LangChain OpenAI library not found. "
                "Install with: pip install langchain-openai"
            )
        
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY not found. "
                "Set environment variable or add to config. "
                "Get your API key from: https://platform.openai.com/api-keys"
            )
        
        try:
            self.backend = ChatOpenAI(
                model=self.model_name,
                openai_api_key=self.api_key,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            self.logger.info(f"Initialized OpenAI provider: {self.model_name}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize OpenAI backend: {e}")
    
    def _format_context(self, context: Optional[List[Any]]) -> List[Union[HumanMessage, AIMessage]]:
        """Format context for LangChain"""
        if not context:
            return []
        
        messages = []
        for msg in context:
            if hasattr(msg, "content"):
                messages.append(msg)
            elif isinstance(msg, dict):
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "user":
                    messages.append(HumanMessage(content=content))
                else:
                    messages.append(AIMessage(content=content))
        
        return messages
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate response using OpenAI"""
        await self._apply_rate_limit()
        
        try:
            messages = []
            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))
            
            messages.extend(self._format_context(context))
            messages.append(HumanMessage(content=prompt))
            
            response = await self.backend.ainvoke(messages)
            return response.content
        except Exception as e:
            self.logger.error(f"OpenAI generation failed: {e}")
            raise
    
    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate response synchronously"""
        self._apply_rate_limit_sync()
        
        try:
            messages = []
            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))
            
            messages.extend(self._format_context(context))
            messages.append(HumanMessage(content=prompt))
            
            response = self.backend.invoke(messages)
            return response.content
        except Exception as e:
            self.logger.error(f"OpenAI sync generation failed: {e}")
            raise
    
    async def generate_with_usage(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
    ) -> dict:
        """Generate response and return full token usage metadata."""
        await self._apply_rate_limit()

        try:
            messages = []
            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))
            messages.extend(self._format_context(context))
            messages.append(HumanMessage(content=prompt))

            response = await self.backend.ainvoke(messages)

            # LangChain exposes usage via response_metadata['token_usage']
            token_usage = response.response_metadata.get("token_usage", {})
            prompt_tokens     = token_usage.get("prompt_tokens", 0)
            completion_tokens = token_usage.get("completion_tokens", 0)
            total_tokens      = token_usage.get("total_tokens", prompt_tokens + completion_tokens)

            return {
                "response":           response.content,
                "reasoning":          "",
                "prompt_tokens":      prompt_tokens,
                "completion_tokens":  completion_tokens,
                "total_tokens":       total_tokens,
                "cost_usd":           self._estimate_cost(prompt_tokens, completion_tokens),
                "model":              self.model_name,
                "provider":           "openai",
            }
        except Exception as e:
            self.logger.error(f"OpenAI generate_with_usage failed: {e}")
            raise

    def get_model_name(self) -> str:
        """Get current model name"""
        return self.model_name

    def is_available(self) -> bool:
        """Check if provider is available"""
        return LANGCHAIN_AVAILABLE and bool(self.api_key) and self.backend is not None

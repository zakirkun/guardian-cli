"""
Claude (Anthropic) Provider Implementation
Anthropic Claude models via Anthropic API
"""

import os
from typing import Optional, Dict, Any, List, Union

try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from ai.providers.base_provider import BaseProvider


class ClaudeProvider(BaseProvider):
    """Anthropic Claude API provider"""
    
    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        
        # Get Claude-specific configuration
        ai_config = config.get("ai", {})
        claude_config = ai_config.get("claude", {})
        
        self.model_name = claude_config.get("model", "claude-3-5-sonnet-20241022")
        # Prefer config file over environment variable
        self.api_key = claude_config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)
        
        self.backend = None
        self._initialize()
    
    def _initialize(self):
        """Initialize Claude backend"""
        if not LANGCHAIN_AVAILABLE:
            raise RuntimeError(
                "LangChain Anthropic library not found. "
                "Install with: pip install langchain-anthropic"
            )
        
        if not self.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not found. "
                "Set environment variable or add to config. "
                "Get your API key from: https://console.anthropic.com/"
            )
        
        try:
            self.backend = ChatAnthropic(
                model=self.model_name,
                anthropic_api_key=self.api_key,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            self.logger.info(f"Initialized Claude provider: {self.model_name}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Claude backend: {e}")
    
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
        """Generate response using Claude"""
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
            self.logger.error(f"Claude generation failed: {e}")
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
            self.logger.error(f"Claude sync generation failed: {e}")
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

            # LangChain-Anthropic stores usage in response_metadata['usage']
            usage = response.response_metadata.get("usage", {})
            prompt_tokens     = usage.get("input_tokens", 0)
            completion_tokens = usage.get("output_tokens", 0)
            total_tokens      = prompt_tokens + completion_tokens

            return {
                "response":           response.content,
                "reasoning":          "",
                "prompt_tokens":      prompt_tokens,
                "completion_tokens":  completion_tokens,
                "total_tokens":       total_tokens,
                "cost_usd":           self._estimate_cost(prompt_tokens, completion_tokens),
                "model":              self.model_name,
                "provider":           "claude",
            }
        except Exception as e:
            self.logger.error(f"Claude generate_with_usage failed: {e}")
            raise

    def get_model_name(self) -> str:
        """Get current model name"""
        return self.model_name

    def is_available(self) -> bool:
        """Check if provider is available"""
        return LANGCHAIN_AVAILABLE and bool(self.api_key) and self.backend is not None

    # ── Vision (A3) ──────────────────────────────────────────────────────────

    def supports_vision(self) -> bool:
        """All Claude 3+ models accept image inputs."""
        m = (self.model_name or "").lower()
        return "claude-3" in m or "claude-4" in m or "claude-sonnet" in m or "claude-opus" in m

    async def generate_with_images(
        self,
        prompt: str,
        images: list,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Anthropic-shaped multimodal call.

        Anthropic accepts images as ``{"type":"image","source":{"type":"base64",
        "media_type":"image/png","data":"..."}}``. LangChain's HumanMessage
        passes content lists through verbatim, so this shape works as-is.
        """
        import base64
        import mimetypes
        from pathlib import Path

        await self._apply_rate_limit() if hasattr(self, "_apply_rate_limit") else None

        content: list = [{"type": "text", "text": prompt}]
        for img in images:
            path = img.get("path") if isinstance(img, dict) else img
            if not path:
                continue
            p = Path(path)
            if not p.exists():
                self.logger.warning(f"Vision: skipping missing image {p}")
                continue
            mime = (img.get("mime") if isinstance(img, dict) else None)
            if not mime:
                mime, _ = mimetypes.guess_type(str(p))
                mime = mime or "image/png"
            with open(p, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
            content.append({
                "type": "image",
                "source": {"type": "base64", "media_type": mime, "data": b64},
            })

        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=content))

        response = await self.backend.ainvoke(messages)
        token_usage = response.response_metadata.get("usage", {}) or response.response_metadata.get("token_usage", {})
        prompt_tokens = token_usage.get("input_tokens", 0) or token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("output_tokens", 0) or token_usage.get("completion_tokens", 0)
        total_tokens = prompt_tokens + completion_tokens

        return {
            "response":           response.content if isinstance(response.content, str) else str(response.content),
            "reasoning":          "",
            "prompt_tokens":      prompt_tokens,
            "completion_tokens":  completion_tokens,
            "total_tokens":       total_tokens,
            "cost_usd":           self._estimate_cost(prompt_tokens, completion_tokens) if hasattr(self, "_estimate_cost") else 0.0,
            "model":              self.model_name,
            "provider":           "claude",
        }

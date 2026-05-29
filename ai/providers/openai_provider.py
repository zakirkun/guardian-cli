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

    # ── Vision (A3) ──────────────────────────────────────────────────────────

    def supports_vision(self) -> bool:
        """gpt-4o / gpt-4-turbo / gpt-4-vision all accept image inputs."""
        m = (self.model_name or "").lower()
        return "gpt-4o" in m or "gpt-4-turbo" in m or "vision" in m

    async def generate_with_usage_with_images(
        self,
        prompt: str,
        images: list,
        system_prompt: str = "",
    ) -> dict:
        """Image-aware variant of generate_with_usage.

        Sends an OpenAI multimodal HumanMessage shaped as
        ``[{type:"text",...}, {type:"image_url", image_url:...}]``.

        Each ``images[i]`` is ``{"path": str}`` — the file is base64-
        encoded and inlined as ``data:`` URL. Remote URLs would also work
        but the screenshot tool only emits local paths.
        """
        import base64
        import mimetypes
        from pathlib import Path

        await self._apply_rate_limit()

        content: list = [{"type": "text", "text": prompt}]
        for img in images:
            path = img.get("path") if isinstance(img, dict) else img
            if not path:
                continue
            p = Path(path)
            if not p.exists():
                self.logger.warning(f"Vision: skipping missing image {p}")
                continue
            mime = img.get("mime") if isinstance(img, dict) else None
            if not mime:
                mime, _ = mimetypes.guess_type(str(p))
                mime = mime or "image/png"
            with open(p, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
            content.append({
                "type": "image_url",
                "image_url": {"url": f"data:{mime};base64,{b64}"},
            })

        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.append(HumanMessage(content=content))

        response = await self.backend.ainvoke(messages)
        token_usage = response.response_metadata.get("token_usage", {})
        prompt_tokens = token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("completion_tokens", 0)
        total_tokens = token_usage.get("total_tokens", prompt_tokens + completion_tokens)

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

    async def generate_with_images(self, prompt, images, system_prompt=None):
        return await self.generate_with_usage_with_images(prompt, images, system_prompt or "")

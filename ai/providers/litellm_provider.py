"""
LiteLLM Provider Implementation
Access 100+ LLM providers (OpenAI, Anthropic, Google, Azure, Bedrock,
Cohere, Mistral, …) through a single unified interface.

Users specify the model with provider-prefixed names, e.g.:
  anthropic/claude-sonnet-4-6
  openai/gpt-4o
  gemini/gemini-2.5-pro
  bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0

Config block in ``guardian.yaml``:

    ai:
      provider: litellm
      litellm:
        model: anthropic/claude-sonnet-4-6
        api_key: null         # Or set provider-specific env vars
        api_base: null        # Optional: proxy URL
        drop_params: true     # Drop unsupported params per provider

Install:  pip install guardian-cli[litellm]
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ai.providers.base_provider import BaseProvider


def _check_litellm():
    try:
        import litellm  # noqa: F401

        return True
    except ImportError:
        return False


class LiteLLMProvider(BaseProvider):
    """LiteLLM AI gateway provider — 100+ LLM providers via one interface."""

    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)

        ai_config = config.get("ai", {})
        litellm_config = ai_config.get("litellm", {})

        self.model_name = litellm_config.get("model") or ai_config.get("model", "openai/gpt-4o")
        self.api_key = litellm_config.get("api_key") or os.environ.get("LITELLM_API_KEY")
        self.api_base = litellm_config.get("api_base") or os.environ.get("LITELLM_API_BASE")
        self.drop_params = litellm_config.get("drop_params", True)
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)

        self._available = False
        self._initialize()

    def _initialize(self):
        if not _check_litellm():
            raise RuntimeError(
                "litellm not installed. Install with: pip install guardian-cli[litellm]"
            )
        self._available = True
        self.logger.info(f"Initialized LiteLLM provider: {self.model_name}")

    def _build_messages(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> List[Dict[str, str]]:
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if context:
            for msg in context:
                if isinstance(msg, dict):
                    messages.append(
                        {
                            "role": msg.get("role", "user"),
                            "content": msg.get("content", ""),
                        }
                    )
                elif hasattr(msg, "content"):
                    role = getattr(msg, "type", "human")
                    if role in ("human", "HumanMessage"):
                        role = "user"
                    elif role in ("ai", "AIMessage"):
                        role = "assistant"
                    elif role in ("system", "SystemMessage"):
                        role = "system"
                    messages.append({"role": role, "content": msg.content})
        messages.append({"role": "user", "content": prompt})
        return messages

    def _base_kwargs(self) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "model": self.model_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "drop_params": self.drop_params,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base
        return kwargs

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        await self._apply_rate_limit()
        import litellm

        messages = self._build_messages(prompt, system_prompt, context)

        async def _call():
            return await litellm.acompletion(messages=messages, **self._base_kwargs())

        response = await self._with_retry(_call, self._is_retriable)
        if not response.choices:
            raise ValueError("LiteLLM returned empty choices list")
        return str(response.choices[0].message.content or "")

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        self._apply_rate_limit_sync()
        import litellm

        messages = self._build_messages(prompt, system_prompt, context)
        kwargs = self._base_kwargs()

        last_err = None
        for attempt in range(max(getattr(self, "_retry_attempts", 2), 1)):
            try:
                response = litellm.completion(messages=messages, **kwargs)
                if not response.choices:
                    raise ValueError("LiteLLM returned empty choices list")
                return str(response.choices[0].message.content or "")
            except Exception as e:
                last_err = e
                if not self._is_retriable(e) or attempt >= self._retry_attempts - 1:
                    raise
                import time

                time.sleep(min(2**attempt, 30))
        raise last_err

    async def generate_with_usage(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
    ) -> Dict[str, Any]:
        await self._apply_rate_limit()
        import litellm

        messages = self._build_messages(prompt, system_prompt, context)

        async def _call():
            return await litellm.acompletion(messages=messages, **self._base_kwargs())

        response = await self._with_retry(_call, self._is_retriable)
        if not response.choices:
            raise ValueError("LiteLLM returned empty choices list")

        usage = getattr(response, "usage", None) or {}
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0
        total_tokens = getattr(usage, "total_tokens", 0) or (prompt_tokens + completion_tokens)

        self._enforce_token_budget(total_tokens)

        return {
            "response": str(response.choices[0].message.content or ""),
            "reasoning": "",
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost_usd": self._estimate_cost(prompt_tokens, completion_tokens),
            "model": self.model_name,
            "provider": "litellm",
        }

    def get_model_name(self) -> str:
        return self.model_name

    def is_available(self) -> bool:
        return self._available

    @staticmethod
    def _is_retriable(exc: BaseException) -> bool:
        qualname = f"{type(exc).__module__}.{type(exc).__name__}"
        if qualname in {
            "litellm.exceptions.RateLimitError",
            "litellm.exceptions.APIConnectionError",
            "litellm.exceptions.Timeout",
            "litellm.exceptions.InternalServerError",
            "litellm.exceptions.ServiceUnavailableError",
            "litellm.exceptions.BadGatewayError",
        }:
            return True
        return BaseProvider.default_is_retriable(exc)

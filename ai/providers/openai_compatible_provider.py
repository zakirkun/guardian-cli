"""
OpenAI-compatible provider — works with any service that exposes the
OpenAI Chat Completions API on a custom base URL.

Tested with:
  * vLLM  (``--api-key`` server flag, OpenAI-compat by default)
  * LM Studio (built-in OpenAI-compat server)
  * Together AI, Groq, Anyscale, Fireworks, DeepInfra
  * Self-hosted llama.cpp ``server`` with ``--api-key``

Config block in ``guardian.yaml``:

    ai:
      provider: openai_compatible
      openai_compatible:
        base_url: http://vllm.local:8000/v1
        model: meta-llama/Llama-3.1-70B-Instruct
        api_key: any-string-or-from-env
        api_key_env: OPENAI_COMPAT_KEY     # alternative
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Union

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    LANGCHAIN_AVAILABLE = False

from ai.providers.base_provider import BaseProvider


class OpenAICompatibleProvider(BaseProvider):
    """OpenAI Chat Completions over a custom base URL."""

    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        ai_config = config.get("ai", {})
        compat = ai_config.get("openai_compatible", {})

        self.model_name = compat.get("model") or ai_config.get("model", "local-model")
        self.base_url = compat.get("base_url") or os.environ.get(
            "OPENAI_COMPAT_BASE_URL"
        )
        # API key: explicit > env from config > generic env > literal "EMPTY"
        # (vLLM accepts any non-empty string when `--api-key` was unset).
        env_key_name = compat.get("api_key_env", "OPENAI_COMPAT_API_KEY")
        self.api_key = (
            compat.get("api_key")
            or os.environ.get(env_key_name)
            or os.environ.get("OPENAI_COMPAT_API_KEY")
            or "EMPTY"
        )
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)

        self.backend = None
        self._initialize()

    def _initialize(self) -> None:
        if not LANGCHAIN_AVAILABLE:
            raise RuntimeError(
                "langchain-openai not installed. Install with: pip install langchain-openai"
            )
        if not self.base_url:
            raise RuntimeError(
                "openai_compatible provider requires `ai.openai_compatible.base_url` "
                "in config or OPENAI_COMPAT_BASE_URL env var."
            )
        try:
            self.backend = ChatOpenAI(
                model=self.model_name,
                openai_api_key=self.api_key,
                openai_api_base=self.base_url,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            self.logger.info(
                f"Initialized openai_compatible provider: "
                f"{self.model_name} @ {self.base_url}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize openai_compatible backend: {e}")

    def _format_context(
        self, context: Optional[List[Any]]
    ) -> List[Union[HumanMessage, AIMessage]]:
        if not context:
            return []
        out: List[Union[HumanMessage, AIMessage]] = []
        for msg in context:
            if hasattr(msg, "content"):
                out.append(msg)
            elif isinstance(msg, dict):
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if role == "user":
                    out.append(HumanMessage(content=content))
                else:
                    out.append(AIMessage(content=content))
        return out

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        await self._apply_rate_limit()
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.extend(self._format_context(context))
        messages.append(HumanMessage(content=prompt))
        response = await self.backend.ainvoke(messages)
        return response.content

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        self._apply_rate_limit_sync()
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.extend(self._format_context(context))
        messages.append(HumanMessage(content=prompt))
        return self.backend.invoke(messages).content

    async def generate_with_usage(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
    ) -> Dict[str, Any]:
        await self._apply_rate_limit()
        messages = []
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        messages.extend(self._format_context(context))
        messages.append(HumanMessage(content=prompt))

        async def _call():
            return await self.backend.ainvoke(messages)

        response = await self._with_retry(_call, BaseProvider.default_is_retriable)

        # Many OpenAI-compat servers omit token_usage. Fall back to a rough
        # estimate (4 chars per token) so cost tracking is at least non-zero.
        token_usage = (response.response_metadata or {}).get("token_usage", {})
        prompt_tokens = token_usage.get("prompt_tokens") or len(prompt) // 4
        completion_tokens = token_usage.get("completion_tokens") or len(response.content) // 4
        total_tokens = token_usage.get("total_tokens") or (prompt_tokens + completion_tokens)

        self._enforce_token_budget(total_tokens)

        return {
            "response": response.content,
            "reasoning": "",
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost_usd": self._estimate_cost(prompt_tokens, completion_tokens),
            "model": self.model_name,
            "provider": "openai_compatible",
        }

    def get_model_name(self) -> str:
        return self.model_name

    def is_available(self) -> bool:
        return (
            LANGCHAIN_AVAILABLE
            and bool(self.base_url)
            and self.backend is not None
        )

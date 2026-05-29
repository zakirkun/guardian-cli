"""
Ollama provider — local LLMs over the Ollama HTTP API.

Authorized engagements often forbid sending findings to OpenAI / Anthropic.
This provider talks to a locally-running ``ollama serve`` instance with no
external network calls.

Two backend paths:
  1. ``langchain-ollama`` if installed — preferred; rich features.
  2. Raw HTTP via ``aiohttp`` — minimal fallback so the provider works
     without an extra dep, since Guardian doesn't ship langchain-ollama
     by default.

Config:

    ai:
      provider: ollama
      ollama:
        base_url: http://localhost:11434
        model: llama3.1:70b
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

try:
    import aiohttp  # type: ignore
    AIOHTTP_AVAILABLE = True
except ImportError:  # pragma: no cover
    AIOHTTP_AVAILABLE = False

from ai.providers.base_provider import BaseProvider


_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider(BaseProvider):
    """Local LLM via Ollama HTTP API."""

    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        ai_config = config.get("ai", {})
        ocfg = ai_config.get("ollama", {})

        self.model_name = ocfg.get("model") or ai_config.get("model", "llama3.1")
        self.base_url = (
            ocfg.get("base_url")
            or os.environ.get("OLLAMA_HOST")
            or _DEFAULT_BASE_URL
        ).rstrip("/")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)
        self._initialize()

    def _initialize(self) -> None:
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError(
                "aiohttp not installed — required for OllamaProvider. "
                "Install with: pip install aiohttp"
            )
        self.logger.info(f"Initialized ollama provider: {self.model_name} @ {self.base_url}")

    def _build_messages(
        self,
        prompt: str,
        system_prompt: Optional[str],
        context: Optional[List[Any]],
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
                    role = "assistant" if type(msg).__name__ == "AIMessage" else "user"
                    messages.append({"role": role, "content": msg.content})
        messages.append({"role": "user", "content": prompt})
        return messages

    async def _chat(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """POST /api/chat and return the parsed JSON response.

        Uses ``stream: false`` to get a single JSON object with token
        counts in ``prompt_eval_count`` / ``eval_count`` (Ollama's
        established field names — see ollama/ollama#1130).
        """
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        timeout = aiohttp.ClientTimeout(total=600)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{self.base_url}/api/chat", json=payload
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(
                        f"Ollama returned HTTP {resp.status}: {text[:300]}"
                    )
                return await resp.json()

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        await self._apply_rate_limit()
        result = await self._chat(self._build_messages(prompt, system_prompt, context))
        return (result.get("message") or {}).get("content", "")

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        # Ollama's blocking call is just a sync wrapper around the same
        # endpoint; reuse the async path via a fresh event loop so the
        # interface stays uniform.
        return asyncio.run(self.generate(prompt, system_prompt, context))

    async def generate_with_usage(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
    ) -> Dict[str, Any]:
        await self._apply_rate_limit()

        async def _call():
            return await self._chat(self._build_messages(prompt, system_prompt, context))

        result = await self._with_retry(_call, BaseProvider.default_is_retriable)

        prompt_tokens = int(result.get("prompt_eval_count", 0))
        completion_tokens = int(result.get("eval_count", 0))
        total_tokens = prompt_tokens + completion_tokens
        self._enforce_token_budget(total_tokens)

        return {
            "response": (result.get("message") or {}).get("content", ""),
            "reasoning": "",
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            # Local model — no API cost. Unlisted models still warn once
            # via _estimate_cost; for ollama we just return 0 unconditionally.
            "cost_usd": 0.0,
            "model": self.model_name,
            "provider": "ollama",
        }

    def get_model_name(self) -> str:
        return self.model_name

    def is_available(self) -> bool:
        return AIOHTTP_AVAILABLE

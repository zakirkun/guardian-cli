"""
Base Provider Interface for AI Models
Defines the common interface that all AI providers must implement,
including generate_with_usage() for token cost tracking.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
import time
import asyncio


def _compute_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    config: Dict[str, Any],
) -> float:
    """
    Calculate estimated USD cost for one AI call using pricing from
    config/guardian.yaml  →  ai.pricing.<model>.{prompt, completion}

    Prices are expressed as USD per 1 million tokens.
    Returns 0.0 if the model is not listed in config (no hardcoded fallback).
    """
    pricing_table: Dict[str, Any] = config.get("ai", {}).get("pricing", {})
    model_pricing = pricing_table.get(model, {})

    prompt_rate      = model_pricing.get("prompt", 0.0)       # USD / 1M tokens
    completion_rate  = model_pricing.get("completion", 0.0)

    cost = (prompt_tokens * prompt_rate + completion_tokens * completion_rate) / 1_000_000
    return round(cost, 8)


class BaseProvider(ABC):
    """Abstract base class for all AI providers"""

    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger

        # Rate limiting
        ai_config = config.get("ai", {})
        self.rate_limit = ai_config.get("rate_limit", 60)
        self._min_request_interval = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
        self._last_request_time = 0.0

    # ── Abstract interface ───────────────────────────────────────────────────

    @abstractmethod
    def _initialize(self):
        """Initialize the provider-specific backend"""
        pass

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        """Generate response asynchronously (text only, no token tracking)"""
        pass

    @abstractmethod
    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        """Generate response synchronously (text only, no token tracking)"""
        pass

    @abstractmethod
    async def generate_with_usage(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Generate a response AND return full token usage metadata.

        Every provider MUST implement this method.

        Returns:
          {
            "response":           str,   # the model's answer
            "reasoning":          str,   # chain-of-thought prefix if available, else ""
            "prompt_tokens":      int,
            "completion_tokens":  int,
            "total_tokens":       int,
            "cost_usd":           float, # estimated from config pricing
            "model":              str,
            "provider":           str,
          }
        """
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Return the current model identifier string"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider is fully initialised and has a valid API key"""
        pass

    # ── Shared helpers ───────────────────────────────────────────────────────

    async def generate_with_reasoning(
        self,
        prompt: str,
        system_prompt: str,
        task_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Backward-compatible wrapper: calls generate_with_usage() and
        returns a dict with at least {"response", "reasoning"}.
        Agents that haven't been updated yet can still call this.
        """
        full_prompt = prompt
        if task_context:
            full_prompt = f"Context: {task_context}\n\n{prompt}"

        result = await self.generate_with_usage(full_prompt, system_prompt)
        return {
            "response":          result["response"],
            "reasoning":         result.get("reasoning", ""),
            "prompt_tokens":     result.get("prompt_tokens", 0),
            "completion_tokens": result.get("completion_tokens", 0),
            "total_tokens":      result.get("total_tokens", 0),
            "cost_usd":          result.get("cost_usd", 0.0),
            "model":             result.get("model", self.get_model_name()),
            "provider":          result.get("provider", "unknown"),
        }

    def _estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Convenience wrapper around the module-level cost function"""
        return _compute_cost(self.get_model_name(), prompt_tokens, completion_tokens, self.config)

    async def _apply_rate_limit(self):
        """Enforce minimum interval between API calls (async)"""
        if self._min_request_interval > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                await asyncio.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _apply_rate_limit_sync(self):
        """Enforce minimum interval between API calls (sync)"""
        if self._min_request_interval > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

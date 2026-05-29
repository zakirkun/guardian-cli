"""
Base Provider Interface for AI Models
Defines the common interface that all AI providers must implement,
including generate_with_usage() for token cost tracking.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Callable, Awaitable
import time
import asyncio
import logging
import random


# Default retry policy for transient provider errors. Tools MAY override per
# call via generate_with_usage(retry_attempts=...).
_DEFAULT_RETRY_ATTEMPTS = 4
_DEFAULT_RETRY_BASE_DELAY = 1.0      # seconds
_DEFAULT_RETRY_MAX_DELAY = 30.0      # seconds


def _compute_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    config: Dict[str, Any],
    logger: Optional[logging.Logger] = None,
    _warned: Optional[set] = None,
) -> float:
    """
    Calculate estimated USD cost for one AI call using pricing from
    config/guardian.yaml  →  ai.pricing.<model>.{prompt, completion}

    Prices are expressed as USD per 1 million tokens.
    Returns 0.0 if the model is not listed in config — and emits a one-shot
    warning so cost-tracking gaps are visible instead of silently
    materialising as $0.00 in reports.
    """
    pricing_table: Dict[str, Any] = config.get("ai", {}).get("pricing", {})
    model_pricing = pricing_table.get(model)

    if not model_pricing:
        if logger is not None and _warned is not None and model not in _warned:
            logger.warning(
                f"No pricing entry for model '{model}' in config.ai.pricing — "
                "cost will be reported as $0.00. Add the model to guardian.yaml "
                "to track spend."
            )
            _warned.add(model)
        return 0.0

    prompt_rate      = model_pricing.get("prompt", 0.0)       # USD / 1M tokens
    completion_rate  = model_pricing.get("completion", 0.0)

    cost = (prompt_tokens * prompt_rate + completion_tokens * completion_rate) / 1_000_000
    return round(cost, 8)


class TokenBudgetExceeded(Exception):
    """Raised when cumulative token usage exceeds the configured budget."""


class BaseProvider(ABC):
    """Abstract base class for all AI providers"""

    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger

        ai_config = config.get("ai", {})

        # Rate limiting (per-instance min interval; not cluster-wide).
        self.rate_limit = ai_config.get("rate_limit", 60)
        self._min_request_interval = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
        self._last_request_time = 0.0
        self._rate_lock = asyncio.Lock()

        # Retry policy.
        self._retry_attempts = ai_config.get("retry_attempts", _DEFAULT_RETRY_ATTEMPTS)
        self._retry_base_delay = ai_config.get("retry_base_delay", _DEFAULT_RETRY_BASE_DELAY)
        self._retry_max_delay = ai_config.get("retry_max_delay", _DEFAULT_RETRY_MAX_DELAY)

        # Token budget — None disables, otherwise hard cap on cumulative tokens.
        # Soft warning fires at 80% so the user has a chance to abort.
        self._token_budget = ai_config.get("token_budget")
        self._token_used = 0
        self._budget_warned = False

        # One-shot pricing-warning set to avoid log spam on every call.
        self._priced_warned: set = set()

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

    # ── Optional vision capability (A3) ──────────────────────────────────────

    def supports_vision(self) -> bool:
        """Whether this provider can ingest image inputs alongside text.

        Default ``False`` — providers that wire image inputs override.
        Callers (e.g. ``visual_triage`` analyst sub-step) check this before
        attempting a vision call so we degrade gracefully on text-only
        providers like Ollama or older OpenAI-compatible endpoints.
        """
        return False

    async def generate_with_images(
        self,
        prompt: str,
        images: List[Any],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a response that conditions on the supplied images.

        ``images`` is a list of dicts with ``{"path": <local file>}`` or
        ``{"data": <bytes>}`` plus optional ``{"mime": "image/png"}``.
        Providers that override this MUST return the same shape as
        ``generate_with_usage``.

        Default implementation raises — operators see a precise failure
        ("provider X has no vision support") rather than silent text-only
        degradation.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement generate_with_images. "
            "Use a vision-capable provider (gpt-4o, claude-3.5-sonnet, gemini-1.5-pro)."
        )

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
        return _compute_cost(
            self.get_model_name(),
            prompt_tokens,
            completion_tokens,
            self.config,
            logger=self.logger,
            _warned=self._priced_warned,
        )

    async def _apply_rate_limit(self):
        """Enforce minimum interval between API calls (async, concurrency-safe)."""
        async with self._rate_lock:
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

    # ── Retry + budget helpers (used by concrete providers) ───────────────────

    async def _with_retry(
        self,
        coro_factory: Callable[[], Awaitable[Any]],
        is_retriable: Callable[[BaseException], bool],
    ) -> Any:
        """Run an async call with exponential backoff on retriable errors.

        ``coro_factory`` must return a *fresh* coroutine each call — don't
        pass the same awaitable twice. ``is_retriable`` decides which
        exceptions are worth retrying (typically 429 / 5xx / network blips).
        """
        delay = self._retry_base_delay
        last_err: Optional[BaseException] = None

        for attempt in range(1, self._retry_attempts + 1):
            try:
                return await coro_factory()
            except Exception as e:
                last_err = e
                if attempt >= self._retry_attempts or not is_retriable(e):
                    raise
                # Full jitter to avoid thundering-herd across concurrent agents.
                sleep_for = min(delay, self._retry_max_delay)
                sleep_for = random.uniform(0, sleep_for)
                self.logger.warning(
                    f"Provider call failed ({type(e).__name__}: {e}); "
                    f"retry {attempt}/{self._retry_attempts} in {sleep_for:.2f}s"
                )
                await asyncio.sleep(sleep_for)
                delay = min(delay * 2, self._retry_max_delay)

        # Unreachable — the loop either returns or raises.
        raise last_err  # type: ignore[misc]

    def _enforce_token_budget(self, total_tokens: int) -> None:
        """Update cumulative usage, warn at 80%, abort at 100%.

        Called by concrete providers right after a successful response.
        Raises ``TokenBudgetExceeded`` when the budget is exhausted; callers
        should propagate (do not swallow) so the workflow can stop cleanly.
        """
        self._token_used += int(total_tokens or 0)
        budget = self._token_budget
        if not budget:
            return
        ratio = self._token_used / budget
        if ratio >= 1.0:
            raise TokenBudgetExceeded(
                f"Token budget exhausted: used {self._token_used:,} of {budget:,}"
            )
        if ratio >= 0.8 and not self._budget_warned:
            self._budget_warned = True
            self.logger.warning(
                f"Token budget at {ratio * 100:.0f}% "
                f"({self._token_used:,} / {budget:,}). Workflow may abort soon."
            )

    @staticmethod
    def default_is_retriable(exc: BaseException) -> bool:
        """Heuristic: retry on rate-limit / 5xx / network errors.

        Concrete providers MAY pass their own predicate that recognises
        provider-specific exception classes (anthropic.APIStatusError, etc.).
        """
        msg = str(exc).lower()
        if "rate limit" in msg or "429" in msg:
            return True
        if any(code in msg for code in (" 500", " 502", " 503", " 504", "timeout")):
            return True
        # Network / transport.
        if isinstance(exc, (asyncio.TimeoutError, ConnectionError)):
            return True
        return False

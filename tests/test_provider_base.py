"""Tests for ai.providers.base_provider hardening."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from ai.providers.base_provider import (
    BaseProvider,
    TokenBudgetExceeded,
    _compute_cost,
)


class _StubProvider(BaseProvider):
    """Minimal concrete provider used to exercise BaseProvider helpers."""

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config, logger=logging.getLogger("test"))

    def _initialize(self) -> None:  # pragma: no cover
        pass

    async def generate(self, prompt: str, system_prompt=None, context=None) -> str:
        return ""

    def generate_sync(self, prompt: str, system_prompt=None, context=None) -> str:
        return ""

    async def generate_with_usage(self, prompt: str, system_prompt: str, context=None):
        return {}

    def get_model_name(self) -> str:
        return "test-model"

    def is_available(self) -> bool:
        return True


@pytest.fixture
def provider(base_config: Dict[str, Any]) -> _StubProvider:
    cfg = dict(base_config)
    cfg["ai"] = {
        "rate_limit": 0,
        "retry_attempts": 3,
        "retry_base_delay": 0.001,
        "retry_max_delay": 0.01,
        "token_budget": 1000,
        "pricing": {"test-model": {"prompt": 1.0, "completion": 2.0}},
    }
    return _StubProvider(cfg)


class TestComputeCost:
    def test_listed_model(self, base_config: Dict[str, Any]) -> None:
        cfg = {"ai": {"pricing": {"x": {"prompt": 5.0, "completion": 15.0}}}}
        # 1000 prompt + 500 completion at $5 / $15 per 1M
        cost = _compute_cost("x", 1000, 500, cfg)
        assert cost == round((1000 * 5 + 500 * 15) / 1_000_000, 8)

    def test_unlisted_model_warns_once(self) -> None:
        cfg = {"ai": {"pricing": {}}}
        warned: set = set()
        log = MagicMock()
        cost1 = _compute_cost("missing", 100, 100, cfg, logger=log, _warned=warned)
        cost2 = _compute_cost("missing", 100, 100, cfg, logger=log, _warned=warned)
        assert cost1 == 0.0 and cost2 == 0.0
        # Log once, not twice.
        assert log.warning.call_count == 1


class TestRetry:
    @pytest.mark.asyncio
    async def test_succeeds_first_try(self, provider: _StubProvider) -> None:
        async def factory():
            return "ok"

        result = await provider._with_retry(factory, lambda e: True)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_retries_on_retriable(self, provider: _StubProvider) -> None:
        calls = {"n": 0}

        async def factory():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ConnectionError("flaky")
            return "ok"

        result = await provider._with_retry(
            factory, BaseProvider.default_is_retriable
        )
        assert result == "ok"
        assert calls["n"] == 3

    @pytest.mark.asyncio
    async def test_raises_after_attempts(self, provider: _StubProvider) -> None:
        async def factory():
            raise ConnectionError("perma")

        with pytest.raises(ConnectionError):
            await provider._with_retry(
                factory, BaseProvider.default_is_retriable
            )

    @pytest.mark.asyncio
    async def test_non_retriable_raises_immediately(
        self, provider: _StubProvider
    ) -> None:
        calls = {"n": 0}

        async def factory():
            calls["n"] += 1
            raise ValueError("bad input")

        with pytest.raises(ValueError):
            await provider._with_retry(factory, lambda e: False)
        assert calls["n"] == 1


class TestRetriableHeuristic:
    def test_429_retriable(self) -> None:
        assert BaseProvider.default_is_retriable(Exception("HTTP 429 too many"))

    def test_500_retriable(self) -> None:
        assert BaseProvider.default_is_retriable(Exception("server error 500"))

    def test_timeout_retriable(self) -> None:
        assert BaseProvider.default_is_retriable(asyncio.TimeoutError())

    def test_validation_not_retriable(self) -> None:
        assert not BaseProvider.default_is_retriable(ValueError("bad json"))


class TestTokenBudget:
    def test_warning_at_80(self, provider: _StubProvider) -> None:
        log_warn = MagicMock()
        provider.logger = MagicMock(warning=log_warn)
        provider._enforce_token_budget(800)  # 80% of 1000
        assert log_warn.call_count == 1
        # Second call past 80% should not re-warn.
        provider._enforce_token_budget(50)
        assert log_warn.call_count == 1

    def test_abort_at_100(self, provider: _StubProvider) -> None:
        with pytest.raises(TokenBudgetExceeded):
            provider._enforce_token_budget(1500)

    def test_no_budget_no_op(self, base_config: Dict[str, Any]) -> None:
        cfg = dict(base_config)
        cfg["ai"] = {"rate_limit": 0}  # no token_budget
        p = _StubProvider(cfg)
        # Should not raise even at huge usage.
        p._enforce_token_budget(10_000_000)

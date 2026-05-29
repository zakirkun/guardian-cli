"""Tests for the judge-model routing in BaseAgent.think_deeply."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.agent import BaseAgent
from core.memory import PentestMemory


class _Probe(BaseAgent):
    """Concrete BaseAgent subclass for tests — execute is a no-op."""

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        return {}


def _make_client(responses: List[Dict[str, Any]]) -> MagicMock:
    """Mock client whose generate_with_usage returns scripted dicts in order."""
    client = MagicMock()
    client.model_name = "gpt-4o"
    client.generate_with_usage = AsyncMock(side_effect=responses)
    client.get_model_name = MagicMock(return_value="gpt-4o")
    return client


def _result(text: str, tokens: int = 100, cost: float = 0.001) -> Dict[str, Any]:
    return {
        "response": text,
        "reasoning": "",
        "prompt_tokens": tokens // 2,
        "completion_tokens": tokens // 2,
        "total_tokens": tokens,
        "cost_usd": cost,
        "model": "gpt-4o",
        "provider": "openai",
    }


@pytest.fixture
def probe(base_config: Dict[str, Any]) -> _Probe:
    cfg = dict(base_config)
    return _Probe(
        name="Probe",
        config=cfg,
        gemini_client=MagicMock(),
        memory=PentestMemory("example.com"),
    )


class TestNoJudgeLegacyBehaviour:
    @pytest.mark.asyncio
    async def test_returns_last_round_when_no_judge(self, probe: _Probe) -> None:
        client = _make_client([
            _result("round1"),
            _result("round2"),
            _result("round3 final"),
        ])
        probe.gemini = client
        out = await probe.think_deeply("Q?", "sys", max_rounds=3)
        assert out["response"] == "round3 final"
        assert out["judge_used"] is False
        assert out["judge_selected_round"] is None
        assert len(out["thinking_chain"]) == 3
        assert out["total_tokens"] == 300


class TestJudgeRouting:
    @pytest.mark.asyncio
    async def test_judge_picks_round_2(self, probe: _Probe) -> None:
        # 3 thinker rounds + 1 judge call returning {selected_round: 2}.
        client = _make_client([
            _result("round1 — weak"),
            _result("round2 — best!"),
            _result("round3 — wandered"),
            _result('{"selected_round": 2, "reason": "most evidence"}', tokens=50),
        ])
        probe.gemini = client
        out = await probe.think_deeply(
            "Q?", "sys", max_rounds=3, judge_model="gpt-4o-mini"
        )
        assert out["judge_used"] is True
        assert out["judge_selected_round"] == 2
        assert out["response"] == "round2 — best!"
        # Judge's tokens are added on top.
        assert out["total_tokens"] == 350

    @pytest.mark.asyncio
    async def test_judge_failure_falls_back(self, probe: _Probe) -> None:
        # Judge returns garbage; must fall back to legacy last-round behaviour.
        client = _make_client([
            _result("round1"),
            _result("round2 last"),
            _result("not json garbage"),
        ])
        probe.gemini = client
        out = await probe.think_deeply(
            "Q?", "sys", max_rounds=2, judge_model="gpt-4o-mini"
        )
        assert out["judge_used"] is False
        assert out["response"] == "round2 last"

    @pytest.mark.asyncio
    async def test_judge_out_of_range_rejected(self, probe: _Probe) -> None:
        client = _make_client([
            _result("a"),
            _result("b"),
            _result('{"selected_round": 99}'),
        ])
        probe.gemini = client
        out = await probe.think_deeply(
            "Q?", "sys", max_rounds=2, judge_model="gpt-4o-mini"
        )
        # Out-of-range pick → judge rejected → legacy fallback.
        assert out["judge_used"] is False
        assert out["response"] == "b"

    @pytest.mark.asyncio
    async def test_judge_skipped_when_only_one_round(self, probe: _Probe) -> None:
        client = _make_client([_result("only round")])
        probe.gemini = client
        out = await probe.think_deeply(
            "Q?", "sys", max_rounds=1, judge_model="gpt-4o-mini"
        )
        # Single round — nothing to judge between. Skip the call entirely.
        assert out["judge_used"] is False
        assert out["response"] == "only round"
        # Client should have been called exactly once (no judge call).
        assert client.generate_with_usage.await_count == 1

    @pytest.mark.asyncio
    async def test_judge_model_from_config(self, probe: _Probe) -> None:
        probe.config = {"ai": {"judge_model": "gpt-4o-mini"}}
        client = _make_client([
            _result("a"),
            _result("b"),
            _result('{"selected_round": 1}'),
        ])
        probe.gemini = client
        out = await probe.think_deeply("Q?", "sys", max_rounds=2)
        assert out["judge_used"] is True
        assert out["response"] == "a"

    @pytest.mark.asyncio
    async def test_judge_model_swapped_and_restored(self, probe: _Probe) -> None:
        client = _make_client([
            _result("a"),
            _result("b"),
            _result('{"selected_round": 1}'),
        ])
        probe.gemini = client
        await probe.think_deeply(
            "Q?", "sys", max_rounds=2, judge_model="gpt-4o-mini"
        )
        # After call returns, original model name should be back.
        assert client.model_name == "gpt-4o"

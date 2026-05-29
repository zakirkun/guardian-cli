"""Tests for the multi-agent debate triage (A2)."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.agents.debate_triage import DebateTriage, DebateVerdict
from core.memory import Finding, PentestMemory


# ── Helpers ──────────────────────────────────────────────────────────────────


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


def _make_client(responses: List[Dict[str, Any]]) -> MagicMock:
    client = MagicMock()
    client.model_name = "gpt-4o"
    client.generate_with_usage = AsyncMock(side_effect=responses)
    client.get_model_name = MagicMock(return_value="gpt-4o")
    return client


def _finding(
    fp_label: str = "MEDIUM",
    sev: str = "high",
    description_extra: str = "",
) -> Finding:
    desc = f"SQL error message reflected. False_Positive: {fp_label}. {description_extra}"
    return Finding(
        id="f1",
        severity=sev,
        title="Possible SQLi",
        description=desc,
        evidence="ORA-00942: table or view does not exist",
        tool="nuclei",
        target="https://example.com",
        timestamp="2026-01-01T00:00:00Z",
    )


@pytest.fixture
def memory() -> PentestMemory:
    m = PentestMemory("example.com")
    m.context["technologies"] = ["nginx", "PHP"]
    return m


# ── _extract_fp_probability ──────────────────────────────────────────────────


class TestFpProbabilityExtraction:
    def test_low(self) -> None:
        f = _finding(fp_label="LOW")
        assert DebateTriage._extract_fp_probability(f) == "LOW"

    def test_medium(self) -> None:
        f = _finding(fp_label="MEDIUM")
        assert DebateTriage._extract_fp_probability(f) == "MEDIUM"

    def test_high(self) -> None:
        f = _finding(fp_label="HIGH")
        assert DebateTriage._extract_fp_probability(f) == "HIGH"

    def test_case_insensitive(self) -> None:
        f = Finding(
            id="x", severity="medium", title="t",
            description="false_positive: medium",
            evidence="", tool="t", target="", timestamp="",
        )
        assert DebateTriage._extract_fp_probability(f) == "MEDIUM"

    def test_default_when_unparseable(self) -> None:
        f = Finding(
            id="x", severity="medium", title="t",
            description="no flag here",
            evidence="", tool="t", target="", timestamp="",
        )
        assert DebateTriage._extract_fp_probability(f) == "MEDIUM"

    def test_default_when_empty_description(self) -> None:
        f = Finding(
            id="x", severity="medium", title="t",
            description="",
            evidence="", tool="t", target="", timestamp="",
        )
        assert DebateTriage._extract_fp_probability(f) == "MEDIUM"


# ── _parse_verdict ───────────────────────────────────────────────────────────


class TestParseVerdict:
    def test_valid_verdict(self) -> None:
        raw = '{"verdict": "REAL", "adjusted_severity": "high", "rationale": "ok", "confidence": 88}'
        out = DebateTriage._parse_verdict(raw)
        assert out["verdict"] == "REAL"
        assert out["adjusted_severity"] == "high"
        assert out["confidence"] == 88

    def test_invalid_verdict_defaults_to_verify(self) -> None:
        raw = '{"verdict": "MAYBE", "adjusted_severity": "high"}'
        out = DebateTriage._parse_verdict(raw)
        assert out["verdict"] == "VERIFY_MANUALLY"

    def test_invalid_severity_defaults_to_medium(self) -> None:
        raw = '{"verdict": "REAL", "adjusted_severity": "extreme"}'
        out = DebateTriage._parse_verdict(raw)
        assert out["adjusted_severity"] == "medium"

    def test_garbage_falls_back(self) -> None:
        out = DebateTriage._parse_verdict("not json at all")
        assert out["verdict"] == "VERIFY_MANUALLY"
        assert out["confidence"] == 50

    def test_confidence_clamped(self) -> None:
        raw = '{"verdict": "REAL", "confidence": 999}'
        out = DebateTriage._parse_verdict(raw)
        assert out["confidence"] == 100

        raw2 = '{"verdict": "REAL", "confidence": -5}'
        out2 = DebateTriage._parse_verdict(raw2)
        assert out2["confidence"] == 0

    def test_confidence_non_int_falls_back(self) -> None:
        raw = '{"verdict": "REAL", "confidence": "high"}'
        out = DebateTriage._parse_verdict(raw)
        assert out["confidence"] == 50

    def test_extracts_json_from_surrounding_text(self) -> None:
        raw = 'Here is my verdict:\n{"verdict": "FALSE_POSITIVE"}\nThanks.'
        out = DebateTriage._parse_verdict(raw)
        assert out["verdict"] == "FALSE_POSITIVE"


# ── _extract_argument ────────────────────────────────────────────────────────


class TestExtractArgument:
    def test_pulls_argument_field(self) -> None:
        raw = '{"argument": "this is exploitable", "confidence": 80}'
        assert DebateTriage._extract_argument(raw) == "this is exploitable"

    def test_falls_back_to_reasoning(self) -> None:
        raw = '{"reasoning": "deep thinking here"}'
        assert DebateTriage._extract_argument(raw) == "deep thinking here"

    def test_falls_back_to_raw_when_no_json(self) -> None:
        raw = "no json output, just words"
        assert DebateTriage._extract_argument(raw) == raw

    def test_falls_back_on_invalid_json(self) -> None:
        raw = "{not valid json}"
        out = DebateTriage._extract_argument(raw)
        assert "not valid json" in out


# ── triage() flow ────────────────────────────────────────────────────────────


class TestTriageFlow:
    @pytest.mark.asyncio
    async def test_skips_when_low_fp(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([])
        triage = DebateTriage(base_config, client, memory)

        verdict = await triage.triage(_finding(fp_label="LOW"))
        assert verdict.triggered is False
        assert verdict.verdict == "REAL"
        # No LLM calls — skipped early.
        assert client.generate_with_usage.await_count == 0

    @pytest.mark.asyncio
    async def test_skips_when_high_fp(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([])
        triage = DebateTriage(base_config, client, memory)

        verdict = await triage.triage(_finding(fp_label="HIGH"))
        assert verdict.triggered is False
        assert verdict.verdict == "FALSE_POSITIVE"
        assert client.generate_with_usage.await_count == 0

    @pytest.mark.asyncio
    async def test_full_debate_real_verdict(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([
            _result('{"argument": "real bug — error leaks DB schema"}'),
            _result('{"argument": "generic banner, not exploitable"}'),
            _result(
                '{"verdict": "REAL", "adjusted_severity": "high", '
                '"rationale": "evidence shows DB error", "confidence": 85}'
            ),
        ])
        triage = DebateTriage(base_config, client, memory)

        verdict = await triage.triage(_finding(fp_label="MEDIUM"))
        assert verdict.triggered is True
        assert verdict.verdict == "REAL"
        assert verdict.adjusted_severity == "high"
        assert verdict.confidence == 85
        assert "real bug" in verdict.red_argument
        assert "generic banner" in verdict.blue_argument
        assert client.generate_with_usage.await_count == 3

    @pytest.mark.asyncio
    async def test_full_debate_fp_verdict(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([
            _result('{"argument": "real"}'),
            _result('{"argument": "fp"}'),
            _result(
                '{"verdict": "FALSE_POSITIVE", "adjusted_severity": "info", '
                '"rationale": "no preconditions met", "confidence": 90}'
            ),
        ])
        triage = DebateTriage(base_config, client, memory)

        verdict = await triage.triage(_finding(fp_label="MEDIUM"))
        assert verdict.triggered is True
        assert verdict.verdict == "FALSE_POSITIVE"
        assert verdict.adjusted_severity == "info"

    @pytest.mark.asyncio
    async def test_judge_garbage_falls_back_to_verify(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([
            _result('{"argument": "real"}'),
            _result('{"argument": "fp"}'),
            _result("totally not json"),
        ])
        triage = DebateTriage(base_config, client, memory)

        verdict = await triage.triage(_finding(fp_label="MEDIUM"))
        assert verdict.triggered is True
        assert verdict.verdict == "VERIFY_MANUALLY"
        assert verdict.confidence == 50

    @pytest.mark.asyncio
    async def test_advocates_get_distinct_system_prompts(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([
            _result('{"argument": "r"}'),
            _result('{"argument": "b"}'),
            _result('{"verdict": "REAL"}'),
        ])
        triage = DebateTriage(base_config, client, memory)

        await triage.triage(_finding(fp_label="MEDIUM"))

        # Inspect each call's system prompt — should differ between roles.
        calls = client.generate_with_usage.await_args_list
        assert len(calls) == 3
        red_sys = calls[0].kwargs["system_prompt"]
        blue_sys = calls[1].kwargs["system_prompt"]
        judge_sys = calls[2].kwargs["system_prompt"]
        assert "RED_ADVOCATE" in red_sys
        assert "BLUE_ADVOCATE" in blue_sys
        assert "JUDGE" in judge_sys
        assert red_sys != blue_sys != judge_sys

    @pytest.mark.asyncio
    async def test_skipped_verdict_has_empty_arguments(
        self, base_config: Dict[str, Any], memory: PentestMemory
    ) -> None:
        client = _make_client([])
        triage = DebateTriage(base_config, client, memory)

        verdict = await triage.triage(_finding(fp_label="LOW"))
        assert verdict.red_argument == ""
        assert verdict.blue_argument == ""
        assert "skipped" in verdict.rationale.lower()


# ── DebateVerdict shape ──────────────────────────────────────────────────────


class TestDebateVerdictShape:
    def test_dataclass_fields(self) -> None:
        v = DebateVerdict(
            finding_id="x",
            verdict="REAL",
            adjusted_severity="high",
            rationale="ok",
            confidence=80,
            red_argument="r",
            blue_argument="b",
            triggered=True,
        )
        assert v.finding_id == "x"
        assert v.triggered is True

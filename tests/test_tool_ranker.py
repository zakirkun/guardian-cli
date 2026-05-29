"""Tests for telemetry export + tool ranker (A5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.telemetry import (
    TelemetryRow,
    _bucket_target,
    export_directory,
    export_session_file,
    session_to_rows,
    write_jsonl,
)
from core.learners.tool_ranker import RankerFeatures, ToolRanker


# ── target bucketing ─────────────────────────────────────────────────────────


class TestBucket:
    def test_url(self) -> None:
        assert _bucket_target("https://example.com/x") == "url"

    def test_ip(self) -> None:
        assert _bucket_target("10.0.0.1") == "ip"

    def test_domain(self) -> None:
        assert _bucket_target("example.com") == "domain"

    def test_unknown(self) -> None:
        assert _bucket_target("") == "unknown"
        assert _bucket_target("not a target") == "unknown"


# ── session_to_rows ──────────────────────────────────────────────────────────


def _state(executions: List[Dict[str, Any]], findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "session_id": "abc",
        "target": "https://example.com",
        "current_phase": "scanning",
        "tool_executions": executions,
        "findings": findings or [],
    }


class TestSessionToRows:
    def test_emits_row_per_execution(self) -> None:
        state = _state([
            {"tool": "httpx", "duration": 1.2, "exit_code": 0, "findings_count": 2},
            {"tool": "nuclei", "duration": 30.0, "exit_code": 0, "findings_count": 5},
        ])
        rows = session_to_rows(state)
        assert len(rows) == 2
        assert rows[0].tool == "httpx"
        assert rows[0].target_type == "url"
        assert rows[0].findings_yielded == 2
        assert rows[1].prior_tool_count == 1
        assert rows[1].prior_findings_count == 2

    def test_no_target_leaks_through(self) -> None:
        state = _state([{"tool": "nmap", "duration": 5, "exit_code": 0}])
        # Field set will not contain 'target'.
        for r in session_to_rows(state):
            for v in vars(r).values():
                assert "https://example.com" not in str(v)

    def test_failed_with_zero_yield_still_recorded(self) -> None:
        state = _state([{"tool": "nmap", "duration": 1, "exit_code": 1, "findings_count": 0}])
        rows = session_to_rows(state)
        assert len(rows) == 1
        assert rows[0].success is False
        assert rows[0].findings_yielded == 0

    def test_findings_count_fallback_from_findings_list(self) -> None:
        state = _state(
            executions=[{"tool": "nuclei", "duration": 1, "exit_code": 0}],
            findings=[{"tool": "nuclei"}, {"tool": "nuclei"}, {"tool": "httpx"}],
        )
        rows = session_to_rows(state)
        assert rows[0].findings_yielded == 2

    def test_empty_state(self) -> None:
        assert session_to_rows({}) == []


# ── export round-trip ────────────────────────────────────────────────────────


class TestExportRoundtrip:
    def test_export_session_file(self, tmp_path: Path) -> None:
        state = _state([{"tool": "httpx", "duration": 1, "exit_code": 0, "findings_count": 1}])
        session_file = tmp_path / "session_1.json"
        session_file.write_text(json.dumps(state), encoding="utf-8")

        out = tmp_path / "out.jsonl"
        n = export_session_file(session_file, out)
        assert n == 1
        contents = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(contents) == 1
        record = json.loads(contents[0])
        assert record["tool"] == "httpx"

    def test_export_directory(self, tmp_path: Path) -> None:
        for i, tool in enumerate(["httpx", "nuclei"]):
            (tmp_path / f"session_{i}.json").write_text(
                json.dumps(_state([{"tool": tool, "duration": 1, "exit_code": 0, "findings_count": 1}])),
                encoding="utf-8",
            )

        out = tmp_path / "all.jsonl"
        n = export_directory(tmp_path, out)
        assert n == 2

    def test_export_directory_skips_malformed(self, tmp_path: Path) -> None:
        (tmp_path / "session_bad.json").write_text("{not json", encoding="utf-8")
        (tmp_path / "session_ok.json").write_text(
            json.dumps(_state([{"tool": "x", "duration": 1, "exit_code": 0, "findings_count": 1}])),
            encoding="utf-8",
        )
        out = tmp_path / "all.jsonl"
        n = export_directory(tmp_path, out)
        assert n == 1


# ── ToolRanker training + prediction ─────────────────────────────────────────


def _row(tool: str, target_type: str = "url", phase: str = "scanning",
         yielded: int = 1, success: bool = True) -> Dict[str, Any]:
    return {
        "tool": tool, "target_type": target_type, "phase": phase,
        "findings_yielded": yielded, "success": success,
        "prior_tool_count": 0, "prior_findings_count": 0,
        "session_id": "x", "duration": 1.0,
    }


class TestRanker:
    def test_empty_predict(self) -> None:
        r = ToolRanker()
        assert r.predict(RankerFeatures(target_type="url", phase="scanning")) == []

    def test_train_returns_count(self) -> None:
        r = ToolRanker()
        n = r.train([_row("httpx"), _row("nuclei")])
        assert n == 2

    def test_dominant_tool_wins(self) -> None:
        r = ToolRanker()
        # nuclei dominates the scanning/url cell.
        rows = [_row("nuclei", yielded=10) for _ in range(5)] + [_row("httpx", yielded=1)]
        r.train(rows)
        ranked = r.predict(RankerFeatures(target_type="url", phase="scanning"), k=2)
        assert ranked[0][0] == "nuclei"
        assert ranked[0][1] > ranked[1][1]

    def test_predict_with_fallback_low_confidence(self) -> None:
        r = ToolRanker(min_confidence=0.99)  # almost always None
        r.train([_row("nuclei", yielded=1), _row("httpx", yielded=1)])
        # Tied scores => ~0.5 probability => below 0.99.
        assert r.predict_with_fallback(RankerFeatures(target_type="url", phase="scanning")) is None

    def test_predict_with_fallback_high_confidence(self) -> None:
        r = ToolRanker(min_confidence=0.4)
        rows = [_row("nuclei", yielded=20) for _ in range(20)]
        r.train(rows)
        assert r.predict_with_fallback(RankerFeatures(target_type="url", phase="scanning")) == "nuclei"

    def test_skipped_failed_rows_excluded(self) -> None:
        r = ToolRanker()
        # Failed runs that yielded nothing don't count.
        bad = [_row("nuclei", yielded=0, success=False) for _ in range(100)]
        good = [_row("httpx", yielded=2)]
        n = r.train(bad + good)
        assert n == 1
        ranked = r.predict(RankerFeatures(target_type="url", phase="scanning"))
        assert ranked[0][0] == "httpx"

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        r = ToolRanker(min_confidence=0.5)
        r.train([_row("nuclei", yielded=5)])
        path = r.save(tmp_path / "ranker.pkl")
        assert path.exists()

        loaded = ToolRanker.load(path)
        assert loaded.min_confidence == 0.5
        assert loaded.predict(RankerFeatures(target_type="url", phase="scanning"))[0][0] == "nuclei"

    def test_train_from_jsonl(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "tel.jsonl"
        with open(jsonl, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(_row("nuclei", yielded=3)) + "\n")
            fh.write("not json\n")
            fh.write(json.dumps(_row("httpx", yielded=1)) + "\n")

        r = ToolRanker()
        n = r.train_from_jsonl(jsonl)
        assert n == 2  # bad line skipped


# ── ranker integration with ToolAgent ────────────────────────────────────────


class TestToolAgentRankerHook:
    """Verify ToolAgent calls the ranker only when use_learned_ranker is on."""

    @pytest.mark.asyncio
    async def test_disabled_by_default(self, base_config: Dict[str, Any]) -> None:
        from core.tool_agent import ToolAgent
        from core.memory import PentestMemory
        from unittest.mock import MagicMock

        memory = PentestMemory("https://example.com")
        ta = ToolAgent(base_config, MagicMock(), memory)
        # _ranker_attempted remains False; ranker not loaded.
        assert ta._predict_with_ranker("url") is None
        assert ta._ranker is None

    @pytest.mark.asyncio
    async def test_enabled_loads_lazily(
        self, base_config: Dict[str, Any], tmp_path: Path
    ) -> None:
        from core.tool_agent import ToolAgent
        from core.memory import PentestMemory
        from unittest.mock import MagicMock

        # Train + save a ranker that confidently picks 'nuclei'.
        r = ToolRanker(min_confidence=0.4)
        r.train([_row("nuclei", yielded=20) for _ in range(20)])
        ranker_path = tmp_path / "ranker.pkl"
        r.save(ranker_path)

        # Patch the default load path.
        import core.learners.tool_ranker as ranker_mod
        old_path = ranker_mod._DEFAULT_MODEL_PATH
        ranker_mod._DEFAULT_MODEL_PATH = ranker_path

        try:
            cfg = dict(base_config)
            cfg["ai"] = {"use_learned_ranker": True}
            memory = PentestMemory("https://example.com")
            memory.update_phase("scanning")
            ta = ToolAgent(cfg, MagicMock(), memory)
            assert ta._predict_with_ranker("url") == "nuclei"
        finally:
            ranker_mod._DEFAULT_MODEL_PATH = old_path

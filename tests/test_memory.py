"""Tests for core.memory — save/load roundtrip + finding linkage."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.memory import Finding, PentestMemory, ThinkingStep, TokenUsage, ToolExecution


def _make_finding(idx: int, exec_id: str = "exec-1") -> Finding:
    return Finding(
        id=f"finding-{idx}",
        severity="high",
        title=f"Issue {idx}",
        description="desc",
        evidence="ev",
        tool="nmap",
        target="example.com",
        timestamp="2026-05-28T00:00:00",
        cvss_score=7.5,
        cwe="CWE-89",
        execution_id=exec_id,
        raw_evidence="raw",
    )


def _make_execution(exec_id: str = "exec-1") -> ToolExecution:
    return ToolExecution(
        id=exec_id,
        tool="nmap",
        command="nmap -sV example.com",
        target="example.com",
        timestamp="2026-05-28T00:00:00",
        exit_code=0,
        output="port 80 open",
        duration=1.23,
    )


class TestRoundtrip:
    def test_empty_memory(self, tmp_path: Path) -> None:
        mem = PentestMemory("example.com", session_id="test-1")
        mem.save_state(tmp_path / "session.json")

        restored = PentestMemory("placeholder")
        assert restored.load_state(tmp_path / "session.json") is True
        assert restored.target == "example.com"
        assert restored.session_id == "test-1"
        assert restored.findings == []
        assert restored.tool_executions == []

    def test_findings_preserve_execution_id(self, tmp_path: Path) -> None:
        mem = PentestMemory("example.com")
        mem.add_tool_execution(_make_execution("exec-42"))
        mem.add_finding(_make_finding(1, exec_id="exec-42"))
        mem.add_finding(_make_finding(2, exec_id="exec-42"))
        mem.save_state(tmp_path / "session.json")

        restored = PentestMemory("placeholder")
        assert restored.load_state(tmp_path / "session.json") is True
        assert len(restored.findings) == 2
        assert all(f.execution_id == "exec-42" for f in restored.findings)
        # Linkage must survive: execution and findings share id.
        assert restored.tool_executions[0].id == "exec-42"

    def test_token_ledger_roundtrip(self, tmp_path: Path) -> None:
        mem = PentestMemory("example.com")
        mem.add_token_usage(
            TokenUsage(
                timestamp="2026-05-28T00:00:00",
                agent="Planner",
                model="gpt-4o",
                provider="openai",
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
                cost_usd=0.0025,
            )
        )
        mem.save_state(tmp_path / "session.json")

        restored = PentestMemory("placeholder")
        restored.load_state(tmp_path / "session.json")
        summary = restored.get_token_summary()
        assert summary["total_tokens"] == 150
        assert summary["by_provider"]["openai"]["calls"] == 1

    def test_thinking_chain_roundtrip(self, tmp_path: Path) -> None:
        mem = PentestMemory("example.com")
        mem.add_thinking_step(
            ThinkingStep(
                timestamp="2026-05-28T00:00:00",
                agent="Planner",
                step_number=1,
                prompt_summary="prompt",
                reasoning="because",
                conclusion="do X",
                tokens_used=10,
            )
        )
        mem.save_state(tmp_path / "session.json")

        restored = PentestMemory("placeholder")
        restored.load_state(tmp_path / "session.json")
        assert len(restored.thinking_chain) == 1
        assert restored.thinking_chain[0].conclusion == "do X"

    def test_load_missing_file_returns_false(self, tmp_path: Path) -> None:
        mem = PentestMemory("example.com")
        assert mem.load_state(tmp_path / "missing.json") is False

    def test_load_corrupt_file_returns_false(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        mem = PentestMemory("example.com")
        assert mem.load_state(bad) is False


class TestFindingsApi:
    def test_severity_filter_excludes_false_positives(self) -> None:
        mem = PentestMemory("example.com")
        good = _make_finding(1)
        bad = _make_finding(2)
        bad.false_positive = True
        mem.add_finding(good)
        mem.add_finding(bad)
        result = mem.get_findings_by_severity("high")
        assert good in result
        assert bad not in result

    def test_summary_counts_by_severity(self) -> None:
        mem = PentestMemory("example.com")
        for sev in ("critical", "high", "high", "low"):
            f = _make_finding(0)
            f.severity = sev
            mem.add_finding(f)
        s = mem.get_findings_summary()
        assert s["critical"] == 1
        assert s["high"] == 2
        assert s["low"] == 1
        assert s["medium"] == 0

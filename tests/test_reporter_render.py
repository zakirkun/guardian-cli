"""Tests for reporter HTML rendering + CVSS-warning injection."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from core.memory import Finding, PentestMemory


def _reporter(base_config: Dict[str, Any]):
    with patch("core.workflow.GeminiClient"):
        from core.reporter_agent import ReporterAgent

        memory = PentestMemory("example.com", session_id="test-1")
        with patch.object(ReporterAgent, "__init__", lambda s, *a, **k: None):
            r = ReporterAgent.__new__(ReporterAgent)
            r.config = base_config
            r.memory = memory
            r.logger = MagicMock()
            return r


def _finding(**kwargs: Any) -> Finding:
    base = {
        "id": "f-1",
        "severity": "high",
        "title": "Test",
        "description": "x" * 600,
        "evidence": "y" * 600,
        "tool": "nmap",
        "target": "example.com",
        "timestamp": "2026-05-28T00:00:00",
    }
    base.update(kwargs)
    return Finding(**base)


class TestMarkdownToHtml:
    def test_bold_renders_correctly(self, base_config: Dict[str, Any]) -> None:
        r = _reporter(base_config)
        # Two bold spans in one paragraph — broke the old converter.
        html = r._markdown_to_html("**foo** and **bar** in one line")
        assert "<strong>foo</strong>" in html
        assert "<strong>bar</strong>" in html

    def test_table_renders(self, base_config: Dict[str, Any]) -> None:
        r = _reporter(base_config)
        md = "| A | B |\n|---|---|\n| 1 | 2 |"
        html = r._markdown_to_html(md)
        assert "<table>" in html
        assert "<td>1</td>" in html

    def test_code_block_preserved(self, base_config: Dict[str, Any]) -> None:
        r = _reporter(base_config)
        md = "```python\nprint('hi')\n```"
        html = r._markdown_to_html(md)
        assert "<code" in html
        assert "print" in html


class TestEvidenceTruncation:
    def test_full_evidence_passed(self, base_config: Dict[str, Any]) -> None:
        r = _reporter(base_config)
        r.memory.add_finding(_finding())
        text = r._format_findings_detailed()
        # Old behaviour: capped at 200. New: 4000 cap.
        assert text.count("y") >= 600

    def test_cvss_mismatch_flagged(self, base_config: Dict[str, Any]) -> None:
        r = _reporter(base_config)
        # Vector recomputes to 9.8; LLM claimed 5.0 → must surface warning.
        r.memory.add_finding(
            _finding(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=5.0,
            )
        )
        text = r._format_findings_detailed()
        assert "does not match claimed score" in text

    def test_cvss_match_no_flag(self, base_config: Dict[str, Any]) -> None:
        r = _reporter(base_config)
        r.memory.add_finding(
            _finding(
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
            )
        )
        text = r._format_findings_detailed()
        assert "does not match" not in text

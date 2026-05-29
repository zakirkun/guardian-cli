"""Tests for core.schemas — Pydantic-validated agent decisions."""

from __future__ import annotations

import pytest

from core.schemas import (
    AnalysisResult,
    FindingModel,
    PlannerDecision,
    ToolSelection,
    parse_or_none,
)


class TestPlannerDecision:
    def test_valid_action_passes(self) -> None:
        d = PlannerDecision(next_action="port_scanning", parameters={"x": 1})
        assert d.next_action == "port_scanning"
        assert d.parameters == {"x": 1}

    def test_unknown_action_rejected(self) -> None:
        with pytest.raises(ValueError):
            PlannerDecision(next_action="rm_rf_slash")

    def test_uppercase_action_normalized(self) -> None:
        d = PlannerDecision(next_action="  PORT_SCANNING  ")
        assert d.next_action == "port_scanning"

    def test_termination_keyword_passes(self) -> None:
        for word in ("done", "complete", "finish", "stop"):
            assert PlannerDecision(next_action=word).next_action == word

    def test_overlong_outcome_rejected(self) -> None:
        with pytest.raises(Exception):
            PlannerDecision(
                next_action="port_scanning",
                expected_outcome="x" * 401,
            )

    def test_phase_transition_optional(self) -> None:
        d = PlannerDecision(next_action="port_scanning", phase_transition="scanning")
        assert d.phase_transition == "scanning"

    def test_extra_fields_ignored(self) -> None:
        d = PlannerDecision(
            next_action="port_scanning",
            evil_field="ignored",
        )
        assert not hasattr(d, "evil_field")


class TestToolSelection:
    def test_known_tool_passes(self) -> None:
        # TOOL_REGISTRY is loaded lazily; use one we know is registered.
        sel = ToolSelection(tool="nmap", arguments="-sV")
        assert sel.tool == "nmap"

    def test_unknown_tool_rejected(self) -> None:
        with pytest.raises(ValueError):
            ToolSelection(tool="totally_made_up_tool")


class TestFindingModel:
    def test_severity_normalized(self) -> None:
        f = FindingModel(severity="HIGH", title="X")
        assert f.severity == "high"

    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(Exception):
            FindingModel(severity="extreme", title="X")

    def test_cvss_score_bounds(self) -> None:
        FindingModel(severity="high", title="X", cvss_score=7.5)
        with pytest.raises(Exception):
            FindingModel(severity="high", title="X", cvss_score=11.0)
        with pytest.raises(Exception):
            FindingModel(severity="high", title="X", cvss_score=-1.0)

    def test_default_fp_low(self) -> None:
        f = FindingModel(severity="medium", title="X")
        assert f.false_positive_probability == "LOW"


class TestParseOrNone:
    def test_parses_dict(self) -> None:
        d = parse_or_none({"next_action": "port_scanning"}, PlannerDecision)
        assert d is not None and d.next_action == "port_scanning"

    def test_parses_json_string(self) -> None:
        d = parse_or_none('{"next_action": "port_scanning"}', PlannerDecision)
        assert d is not None and d.next_action == "port_scanning"

    def test_invalid_returns_none(self) -> None:
        assert parse_or_none('{"next_action": "rm -rf"}', PlannerDecision) is None
        assert parse_or_none("not json", PlannerDecision) is None
        assert parse_or_none(None, PlannerDecision) is None

    def test_passthrough_existing_model(self) -> None:
        d = PlannerDecision(next_action="done")
        assert parse_or_none(d, PlannerDecision) is d


class TestAnalysisResult:
    def test_findings_list(self) -> None:
        r = AnalysisResult(
            findings=[
                {"severity": "HIGH", "title": "SQLi"},
                {"severity": "low", "title": "Banner"},
            ],
            summary="ok",
        )
        assert len(r.findings) == 2
        assert r.findings[0].severity == "high"

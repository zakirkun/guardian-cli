"""Tests for the confirmation gate in core.workflow.

The gate enforces three rules:
  * passive tools never prompt
  * destructive tools are blocked in safe_mode (regardless of --yes)
  * active/intrusive tools prompt unless --yes or require_confirmation=False
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


def _engine(base_config: Dict[str, Any], **overrides: Any):
    """Build a WorkflowEngine with stubbed AI client + agents.

    The engine constructor does heavy work (instantiates 4 agents). We patch
    the AI factory + agents to no-op so tests are fast and offline.
    """
    cfg = dict(base_config)
    cfg.setdefault("pentest", {}).update(overrides.get("pentest", {}))
    cfg.setdefault("ai", {})

    with patch("core.workflow.GeminiClient") as gem, patch(
        "core.planner.PlannerAgent.__init__", return_value=None
    ), patch("core.tool_agent.ToolAgent.__init__", return_value=None), patch(
        "core.analyst_agent.AnalystAgent.__init__", return_value=None
    ), patch("core.reporter_agent.ReporterAgent.__init__", return_value=None):
        gem.return_value = MagicMock()
        from core.workflow import WorkflowEngine

        return WorkflowEngine(cfg, "example.com", assume_yes=overrides.get("assume_yes", False))


class TestConfirmTool:
    def test_passive_never_prompts(self, base_config: Dict[str, Any]) -> None:
        engine = _engine(base_config, pentest={"require_confirmation": True, "safe_mode": True})
        with patch("typer.confirm") as confirm:
            assert engine._confirm_tool("subfinder", {"name": "x"}) is True
            confirm.assert_not_called()

    def test_active_prompts_when_required(self, base_config: Dict[str, Any]) -> None:
        engine = _engine(base_config, pentest={"require_confirmation": True, "safe_mode": True})
        with patch("typer.confirm", return_value=True) as confirm:
            assert engine._confirm_tool("nmap", {"name": "x"}) is True
            confirm.assert_called_once()

    def test_user_decline_blocks(self, base_config: Dict[str, Any]) -> None:
        engine = _engine(base_config, pentest={"require_confirmation": True, "safe_mode": True})
        with patch("typer.confirm", return_value=False):
            assert engine._confirm_tool("nuclei", {"name": "x"}) is False

    def test_yes_flag_skips_prompt(self, base_config: Dict[str, Any]) -> None:
        engine = _engine(
            base_config,
            pentest={"require_confirmation": True, "safe_mode": True},
            assume_yes=True,
        )
        with patch("typer.confirm") as confirm:
            assert engine._confirm_tool("nuclei", {"name": "x"}) is True
            confirm.assert_not_called()

    def test_require_false_skips_prompt(self, base_config: Dict[str, Any]) -> None:
        engine = _engine(base_config, pentest={"require_confirmation": False, "safe_mode": True})
        with patch("typer.confirm") as confirm:
            assert engine._confirm_tool("nikto", {"name": "x"}) is True
            confirm.assert_not_called()

    def test_destructive_blocked_in_safe_mode(self, base_config: Dict[str, Any]) -> None:
        engine = _engine(
            base_config,
            pentest={"require_confirmation": False, "safe_mode": True},
            assume_yes=True,  # even with --yes
        )
        # sqlmap is destructive — must be refused.
        assert engine._confirm_tool("sqlmap", {"name": "x"}) is False

    def test_destructive_allowed_when_safe_mode_off(
        self, base_config: Dict[str, Any]
    ) -> None:
        engine = _engine(
            base_config,
            pentest={"require_confirmation": False, "safe_mode": False},
            assume_yes=True,
        )
        assert engine._confirm_tool("sqlmap", {"name": "x"}) is True

    def test_unknown_tool_treated_as_active(
        self, base_config: Dict[str, Any]
    ) -> None:
        engine = _engine(base_config, pentest={"require_confirmation": True, "safe_mode": True})
        with patch("typer.confirm", return_value=False):
            assert engine._confirm_tool("totally_new_tool", {"name": "x"}) is False

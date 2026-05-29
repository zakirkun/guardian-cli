"""Tests for the resume / atomic-checkpoint logic in core.workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


def _engine(base_config: Dict[str, Any], save_path: Path):
    cfg = dict(base_config)
    cfg["output"] = {"save_path": str(save_path), "format": "markdown"}
    cfg["pentest"] = {"safe_mode": True, "require_confirmation": False}
    cfg["ai"] = {}

    with patch("core.workflow.GeminiClient") as gem, patch(
        "core.planner.PlannerAgent.__init__", return_value=None
    ), patch("core.tool_agent.ToolAgent.__init__", return_value=None), patch(
        "core.analyst_agent.AnalystAgent.__init__", return_value=None
    ), patch("core.reporter_agent.ReporterAgent.__init__", return_value=None):
        gem.return_value = MagicMock()
        from core.workflow import WorkflowEngine

        return WorkflowEngine(cfg, "example.com")


class TestAtomicSave:
    def test_save_creates_session_file(
        self, base_config: Dict[str, Any], tmp_path: Path
    ) -> None:
        engine = _engine(base_config, tmp_path)
        engine._save_session()

        files = list(tmp_path.glob("session_*.json"))
        assert len(files) == 1
        # No leftover temp files.
        temps = list(tmp_path.glob(".session_*.tmp"))
        assert temps == []

    def test_save_overwrites_atomically(
        self, base_config: Dict[str, Any], tmp_path: Path
    ) -> None:
        engine = _engine(base_config, tmp_path)
        engine._save_session()
        # Mutate then save again — file should be replaced, not appended.
        engine.memory.update_phase("scanning")
        engine._save_session()
        files = list(tmp_path.glob("session_*.json"))
        assert len(files) == 1
        contents = files[0].read_text(encoding="utf-8")
        assert "scanning" in contents


class TestResume:
    def test_resume_loads_state(
        self, base_config: Dict[str, Any], tmp_path: Path
    ) -> None:
        engine = _engine(base_config, tmp_path)
        engine.memory.completed_actions.append("recon")
        engine.memory.update_phase("scanning")
        sid = engine.memory.session_id
        engine._save_session()

        # Fresh engine, no state.
        engine2 = _engine(base_config, tmp_path)
        assert engine2.resume_session(sid) is True
        assert engine2.memory.current_phase == "scanning"
        assert "recon" in engine2.memory.completed_actions
        # current_step starts at 1 (already-completed action skipped on resume).
        assert engine2.current_step == 1

    def test_resume_missing_returns_false(
        self, base_config: Dict[str, Any], tmp_path: Path
    ) -> None:
        engine = _engine(base_config, tmp_path)
        assert engine.resume_session("nonexistent") is False

    def test_resume_corrupt_returns_false(
        self, base_config: Dict[str, Any], tmp_path: Path
    ) -> None:
        engine = _engine(base_config, tmp_path)
        bad = tmp_path / "session_bad.json"
        bad.write_text("{ corrupt")
        assert engine.resume_session("bad") is False

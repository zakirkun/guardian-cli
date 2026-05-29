"""Compile every shipped workflow YAML to ensure DSL v2 compatibility."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.workflow_schema import compile_workflow


WORKFLOWS_DIR = Path(__file__).resolve().parents[1] / "workflows"


@pytest.mark.parametrize(
    "yaml_path",
    sorted(WORKFLOWS_DIR.glob("*.yaml")),
    ids=lambda p: p.name,
)
def test_shipped_workflow_compiles(yaml_path: Path) -> None:
    """Every shipped workflow must compile under v2 (with v1→v2 migration).

    Autonomous-mode docs compile to an empty plan — the engine routes them
    to ``run_autonomous`` instead of executing the levels.
    """
    with open(yaml_path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    compiled = compile_workflow(doc)
    is_autonomous = (
        str(doc.get("mode", "")).lower() == "autonomous"
        or not doc.get("steps")
    )
    if is_autonomous:
        assert compiled.steps == {} and compiled.levels == []
        return
    assert len(compiled.levels) > 0, f"{yaml_path.name} compiled to zero levels"
    flat = [sid for lvl in compiled.levels for sid in lvl]
    assert sorted(flat) == sorted(compiled.steps.keys())

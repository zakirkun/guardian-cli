"""
Microsoft PyRIT wrapper — multi-turn LLM red-teaming.

Unlike garak's single-turn probe library, PyRIT orchestrates
adversary-victim conversations with goal-driven attacks (jailbreak,
prompt-leak, harmful-content). Output is a SQLite or JSON database of
attack runs.

Risk class: ``intrusive``. Operator must point ``target`` at the model
endpoint URL or model name.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class PyritTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # PyRIT ships as a Python package; CLI is "pyrit".
        self.tool_name = "pyrit"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("pyrit", {})
        scenario = kwargs.get("scenario", cfg.get("scenario", "jailbreak"))
        out_path = kwargs.get("out_path") or tempfile.mktemp(
            prefix="pyrit_", suffix=".json"
        )
        self._out_path = Path(out_path)
        cmd: List[str] = [
            "pyrit",
            "--scenario", scenario,
            "--target-endpoint", target,
            "--output", str(self._out_path),
            "--max-turns", str(int(kwargs.get("max_turns", cfg.get("max_turns", 5)))),
        ]
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "successful_attacks": 0,
            "total_attempts": 0,
            "by_scenario": {},
            "transcripts": [],
        }
        if not self._out_path.exists():
            return result
        try:
            doc = json.loads(self._out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return result

        runs = doc.get("runs", []) if isinstance(doc, dict) else doc
        for run in runs or []:
            result["total_attempts"] += 1
            scenario = run.get("scenario", "unknown")
            result["by_scenario"][scenario] = result["by_scenario"].get(scenario, 0) + 1
            if run.get("succeeded") or run.get("success"):
                result["successful_attacks"] += 1
                result["transcripts"].append({
                    "scenario": scenario,
                    "goal": (run.get("goal") or "")[:200],
                    "final_response": (run.get("final_response") or "")[:300],
                })
        return result

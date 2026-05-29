"""
Semgrep wrapper — SAST with hosted + community rule packs.

Semgrep emits ``--json`` natively. We invoke ``semgrep scan`` (the
modern subcommand) with a configurable ruleset (default ``auto``, which
picks language-appropriate registry packs). Risk class: ``passive`` —
purely static analysis on the supplied path.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class SemgrepTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "semgrep"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("semgrep", {})
        ruleset = kwargs.get("config", cfg.get("config", "auto"))
        severity = kwargs.get("severity", cfg.get("severity"))
        cmd: List[str] = ["semgrep", "scan", "--config", ruleset, "--json", "--quiet", target]
        if severity:
            sev = ",".join(severity) if isinstance(severity, list) else severity
            cmd.extend(["--severity", sev])
        if kwargs.get("metrics_off", cfg.get("metrics_off", True)):
            cmd.append("--metrics=off")
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "results": [],
            "by_severity": {"ERROR": 0, "WARNING": 0, "INFO": 0},
            "errors": [],
            "result_count": 0,
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        for r in doc.get("results", []) or []:
            extra = r.get("extra", {}) or {}
            sev = (extra.get("severity") or "INFO").upper()
            result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1
            result["results"].append({
                "check_id": r.get("check_id"),
                "path": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "severity": sev,
                "message": extra.get("message", ""),
                "cwe": extra.get("metadata", {}).get("cwe", []),
                "owasp": extra.get("metadata", {}).get("owasp", []),
                "fix": extra.get("fix"),
            })
        result["result_count"] = len(result["results"])
        result["errors"] = doc.get("errors", []) or []
        return result

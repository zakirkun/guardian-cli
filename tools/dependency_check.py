"""
OWASP Dependency-Check wrapper.

Java-based CLI tool that detects publicly-disclosed CVEs in project
dependencies. Slow first run (NVD database download) but stable.

Default output: JSON report at ``--out <dir>``. Risk class: ``passive``.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class DependencyCheckTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Binary is "dependency-check" on most distributions; some package
        # under "dependency-check.sh".
        self.tool_name = "dependency-check"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("dependency-check", {})
        out_dir = kwargs.get("out_dir") or tempfile.mkdtemp(prefix="depcheck_")
        self._out_dir = Path(out_dir)
        cmd: List[str] = [
            "dependency-check",
            "--scan", target,
            "--out", str(self._out_dir),
            "--format", "JSON",
            "--noupdate" if cfg.get("noupdate", False) else "--enableExperimental",
        ]
        project = kwargs.get("project", cfg.get("project", "guardian"))
        cmd.extend(["--project", project])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "vulnerabilities": [],
            "dependency_count": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        }
        report = self._out_dir / "dependency-check-report.json"
        if not report.exists():
            return result
        try:
            doc = json.loads(report.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return result

        deps = doc.get("dependencies", []) or []
        result["dependency_count"] = len(deps)
        for dep in deps:
            for vuln in dep.get("vulnerabilities", []) or []:
                sev = (vuln.get("severity") or "MEDIUM").upper()
                result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1
                result["vulnerabilities"].append({
                    "name": vuln.get("name"),
                    "severity": sev,
                    "cvss": vuln.get("cvssv3", {}).get("baseScore"),
                    "dependency": dep.get("fileName"),
                    "description": (vuln.get("description") or "")[:500],
                })
        return result

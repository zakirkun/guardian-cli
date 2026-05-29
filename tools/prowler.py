"""
Prowler wrapper — AWS-focused CIS / NIST / PCI compliance scanner.

Prowler 4.x uses ``-M json-asff`` (or ``json-ocsf``) for machine-parseable
output. We use the OCSF format — open standard, easier downstream
correlation. Risk class: ``passive`` — read-only AWS API calls.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ProwlerTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "prowler"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("prowler", {})
        provider = (target or kwargs.get("provider") or cfg.get("provider", "aws")).lower()

        out_dir = kwargs.get("output_directory") or tempfile.mkdtemp(prefix="prowler_")
        self._out_dir = Path(out_dir)
        self._out_basename = "guardian-prowler"

        cmd: List[str] = [
            "prowler", provider,
            "-M", "json-ocsf",
            "-o", str(self._out_dir),
            "-F", self._out_basename,
        ]
        services = kwargs.get("services", cfg.get("services"))
        if services:
            services_str = ",".join(services) if isinstance(services, list) else str(services)
            cmd.extend(["--services", services_str])
        severity = kwargs.get("severity", cfg.get("severity"))
        if severity:
            sev_str = ",".join(severity) if isinstance(severity, list) else str(severity)
            cmd.extend(["--severity", sev_str])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "findings": [],
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
            "fail_count": 0,
            "pass_count": 0,
        }
        try:
            ocsf = self._out_dir / f"{self._out_basename}.ocsf.json"
            if not ocsf.exists():
                return result
            doc = json.loads(ocsf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return result

        # OCSF returns a list of detection findings.
        for f in doc if isinstance(doc, list) else []:
            severity = (f.get("severity") or "informational").lower()
            status = (f.get("status_code") or f.get("status", "")).lower()
            if status in ("fail", "failed"):
                result["fail_count"] += 1
            elif status in ("pass", "passed"):
                result["pass_count"] += 1
            result["by_severity"][severity] = result["by_severity"].get(severity, 0) + 1
            if status not in ("pass", "passed"):
                finding_info = (f.get("finding_info") or {})
                result["findings"].append({
                    "title": finding_info.get("title", f.get("activity_name", "")),
                    "severity": severity,
                    "status": status,
                    "resource": (f.get("resources") or [{}])[0].get("uid", ""),
                    "description": finding_info.get("desc", ""),
                })
        return result

"""
Grype wrapper — CVE scanner that consumes SBOMs or scans images directly.

Pairs naturally with Syft (item 12 in the roadmap): pipe ``syft`` JSON into
``grype`` for offline-after-first-fetch CVE assessment. Risk class: ``passive``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class GrypeTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "grype"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("grype", {})
        only_fixed = kwargs.get("only_fixed", cfg.get("only_fixed", False))
        cmd: List[str] = ["grype", target, "-o", "json", "--quiet"]
        if only_fixed:
            cmd.append("--only-fixed")
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "matches": [],
            "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0},
            "match_count": 0,
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        for m in doc.get("matches", []) or []:
            v = m.get("vulnerability", {}) or {}
            artifact = m.get("artifact", {}) or {}
            sev = (v.get("severity") or "Unknown")
            # Normalise to title case (Grype uses Title; older versions use UPPER).
            sev_norm = sev.title() if sev else "Unknown"
            result["by_severity"][sev_norm] = result["by_severity"].get(sev_norm, 0) + 1
            result["matches"].append({
                "id": v.get("id"),
                "severity": sev_norm,
                "package": artifact.get("name"),
                "version": artifact.get("version"),
                "fix": (v.get("fix") or {}).get("versions", []),
                "description": v.get("description", ""),
            })
        result["match_count"] = len(result["matches"])
        return result

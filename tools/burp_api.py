"""
Burp Suite Pro REST API client.

Burp Pro exposes a REST API for scan management. Operator runs Burp
with ``--user-config-file=...`` and the REST API enabled, supplies the
API key in config, and Guardian schedules scans + ingests issues.

Wrapper invokes ``curl`` against the local Burp REST endpoint to keep
deps minimal. Risk class: ``intrusive``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class BurpApiTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Same binary-strategy as the ZAP wrapper.
        self.tool_name = "curl"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("burp", {})
        api_url = kwargs.get("api_url", cfg.get("api_url", "http://localhost:1337"))
        api_key = kwargs.get("api_key", cfg.get("api_key", ""))
        action = kwargs.get("action", cfg.get("action", "issues"))

        if action == "scan":
            endpoint = f"{api_url}/{api_key}/v0.1/scan"
            payload = json.dumps({"urls": [target], "scope": {"include": [{"rule": target}]}})
            return [
                "curl", "-sS", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload, endpoint,
            ]
        elif action == "issues":
            scan_id = kwargs.get("scan_id", "")
            endpoint = f"{api_url}/{api_key}/v0.1/scan/{scan_id}"
            return ["curl", "-sS", endpoint]
        else:
            return ["curl", "-sS", api_url]

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "issues": [],
            "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
            "scan_status": None,
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        result["scan_status"] = doc.get("scan_status")
        for issue in doc.get("issue_events", []) or []:
            issue_data = issue.get("issue", issue) or {}
            sev = (issue_data.get("severity") or "info").lower()
            result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1
            result["issues"].append({
                "name": issue_data.get("name"),
                "severity": sev,
                "confidence": issue_data.get("confidence"),
                "path": issue_data.get("path"),
                "description_html": (issue_data.get("description_html") or "")[:500],
            })
        return result

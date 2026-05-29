"""
MobSF wrapper — REST API client for the Mobile Security Framework.

Operator runs MobSF as a docker container or local install. Wrapper
uploads an APK/IPA and polls for the JSON report. Risk class:
``passive`` — purely static analysis on the supplied artifact.

Operator config:

    ai:
      ...
    tools:
      mobsf:
        api_url: http://localhost:8000
        api_key: <api-key from MobSF settings>
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class MobSFTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "curl"  # MobSF runs as docker; we hit its REST API

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("mobsf", {})
        api_url = kwargs.get("api_url", cfg.get("api_url", "http://localhost:8000"))
        api_key = kwargs.get("api_key", cfg.get("api_key", ""))
        action = kwargs.get("action", cfg.get("action", "scan_report"))

        # ``target`` is the APK/IPA file path. MobSF's three-step flow:
        # upload → scan → report.
        if action == "upload":
            return [
                "curl", "-sS", "-X", "POST",
                "-H", f"Authorization: {api_key}",
                "-F", f"file=@{target}",
                f"{api_url}/api/v1/upload",
            ]
        elif action == "scan":
            scan_hash = kwargs.get("hash", "")
            return [
                "curl", "-sS", "-X", "POST",
                "-H", f"Authorization: {api_key}",
                "-d", f"hash={scan_hash}",
                f"{api_url}/api/v1/scan",
            ]
        else:  # scan_report
            scan_hash = kwargs.get("hash", "")
            return [
                "curl", "-sS", "-X", "POST",
                "-H", f"Authorization: {api_key}",
                "-d", f"hash={scan_hash}",
                f"{api_url}/api/v1/report_json",
            ]

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "package": "",
            "risk_score": None,
            "permissions": [],
            "findings": [],
            "by_severity": {"high": 0, "warning": 0, "info": 0, "secure": 0},
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        result["package"] = doc.get("package_name") or doc.get("app_name", "")
        result["risk_score"] = doc.get("security_score") or doc.get("appsec", {}).get("security_score")

        # Permissions list
        for perm in (doc.get("permissions") or {}).keys():
            result["permissions"].append(perm)

        # Findings: code_analysis is a dict of rule_id → finding details.
        for rule_id, finding in (doc.get("code_analysis") or {}).items():
            sev = (finding.get("metadata", {}).get("severity") or "info").lower()
            result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1
            result["findings"].append({
                "rule": rule_id,
                "severity": sev,
                "description": (finding.get("metadata", {}).get("description") or "")[:300],
                "owasp_mobile": finding.get("metadata", {}).get("owasp-mobile"),
                "cwe": finding.get("metadata", {}).get("cwe"),
            })
        return result

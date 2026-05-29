"""
OWASP ZAP REST API client.

ZAP exposes a control plane on http://localhost:8080 (or wherever the
``-daemon -port`` was started). We invoke the REST endpoints directly
via ``curl`` so the wrapper stays binary-only — no extra Python deps,
just the ``zap-baseline.py``/``zap.sh`` daemon running.

Operator workflow:
  1. Start ZAP in daemon mode: ``zap.sh -daemon -port 8090 -config api.key=...``
  2. Run Guardian workflow: ``guardian workflow run --name api_pentest_v2 ...``

Risk class: ``intrusive`` — ZAP runs active scans by default.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ZapApiTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # ``curl`` is the actual binary the wrapper invokes; ZAP itself runs
        # out-of-band as a daemon. We label the wrapper "zap" for the registry.
        self.tool_name = "curl"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("zap", {})
        api_url = kwargs.get("api_url", cfg.get("api_url", "http://localhost:8090"))
        api_key = kwargs.get("api_key", cfg.get("api_key", ""))
        action = kwargs.get("action", cfg.get("action", "ascan"))

        # Action selector → ZAP REST endpoint.
        endpoints = {
            "spider":  f"{api_url}/JSON/spider/action/scan/?url={target}",
            "ascan":   f"{api_url}/JSON/ascan/action/scan/?url={target}",
            "alerts":  f"{api_url}/JSON/core/view/alerts/?baseurl={target}",
            "passive": f"{api_url}/JSON/pscan/view/recordsToScan/",
        }
        endpoint = endpoints.get(action, endpoints["alerts"])
        if api_key:
            sep = "&" if "?" in endpoint else "?"
            endpoint = f"{endpoint}{sep}apikey={api_key}"

        cmd: List[str] = ["curl", "-sS", "--max-time", "30", endpoint]
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "alerts": [],
            "by_risk": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
            "scan_id": None,
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        # ascan/spider response: {"scan": "<id>"}
        if "scan" in doc:
            result["scan_id"] = doc["scan"]
            return result

        # alerts response: {"alerts": [{"alert": "...", "risk": "High", ...}]}
        for alert in doc.get("alerts", []) or []:
            risk = alert.get("risk", "Informational")
            result["by_risk"][risk] = result["by_risk"].get(risk, 0) + 1
            result["alerts"].append({
                "name": alert.get("alert"),
                "risk": risk,
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "cwe": alert.get("cweid"),
                "wasc": alert.get("wascid"),
                "description": (alert.get("description") or "")[:500],
            })
        return result

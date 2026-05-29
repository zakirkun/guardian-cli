"""
kube-bench wrapper — CIS Kubernetes Benchmark scanner.

Runs as a privileged in-cluster job in production; here we shell out to the
locally-installed binary which assesses node and control-plane configuration.
Output parsed from JSON. Risk class: ``passive`` (read-only inspection).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class KubeBenchTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # kube-bench binary is "kube-bench" (with a hyphen) — override the
        # auto-derived "kubebench" lower-case mash.
        self.tool_name = "kube-bench"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        # ``target`` is unused for cluster-local scans; accepted for interface
        # uniformity. ``targets`` arg can override which CIS section runs.
        cfg = self.config.get("tools", {}).get("kube-bench", {})
        sections = kwargs.get("targets", cfg.get("targets"))
        cmd: List[str] = ["kube-bench", "--json"]
        if sections:
            cmd.extend(["--targets", sections])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "controls": [],
            "totals": {"pass": 0, "fail": 0, "warn": 0, "info": 0},
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        # kube-bench JSON: top-level "Controls" or "Totals". Both shapes seen
        # depending on version — handle either.
        controls = doc.get("Controls") or [doc] if "tests" in doc else doc.get("Controls", [])
        for ctrl in controls or []:
            for test in ctrl.get("tests", []) or []:
                for r in test.get("results", []) or []:
                    status = (r.get("status") or "info").lower()
                    if status in result["totals"]:
                        result["totals"][status] += 1
                    result["controls"].append({
                        "id": r.get("test_number"),
                        "description": r.get("test_desc"),
                        "status": status,
                        "remediation": r.get("remediation", ""),
                        "expected_result": r.get("expected_result", ""),
                    })
        return result

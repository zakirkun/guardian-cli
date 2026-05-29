"""
ScoutSuite wrapper — multi-cloud security audit (AWS / Azure / GCP / OCI).

ScoutSuite emits an HTML report by default; we pin ``--report-dir`` to a
known temp location and parse the JSON sibling file. Risk class: ``passive``
— uses read-only API calls under the operator's existing cloud credentials.

The ``target`` parameter selects the provider (aws|azure|gcp|aliyun|oci).
Operator credentials are picked up from the environment in the standard
provider-specific way (AWS_PROFILE, AZURE creds, gcloud auth, etc).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


_VALID_PROVIDERS = {"aws", "azure", "gcp", "aliyun", "oci"}


class ScoutSuiteTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # PyPI package name is "scoutsuite" — invoked as a console script of
        # the same name.
        self.tool_name = "scout"  # binary in PATH after pip install

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("scoutsuite", {})
        provider = (target or kwargs.get("provider") or cfg.get("provider", "aws")).lower()
        if provider not in _VALID_PROVIDERS:
            provider = "aws"

        report_dir = kwargs.get("report_dir") or tempfile.mkdtemp(prefix="scoutsuite_")
        self._report_dir = Path(report_dir)

        cmd: List[str] = ["scout", provider, "--report-dir", str(self._report_dir),
                          "--no-browser", "--force"]
        # Provider-specific knobs.
        if provider == "aws":
            profile = kwargs.get("profile", cfg.get("profile"))
            if profile:
                cmd.extend(["--profile", profile])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse ScoutSuite's JSON report.

        ScoutSuite writes ``<report_dir>/scoutsuite-results/scoutsuite_results_*.js``
        as JSONP (a JS variable assignment). We strip the prefix and parse
        the remainder. Falls back to summarising stdout if the file is
        missing.
        """
        result: Dict[str, Any] = {"findings": [], "by_severity": {}, "services": []}
        try:
            results_root = self._report_dir / "scoutsuite-results"
            json_files = list(results_root.glob("scoutsuite_results_*.js"))
            if not json_files:
                return result
            raw = json_files[0].read_text(encoding="utf-8", errors="replace")
            # Format is "scoutsuite_results = { ... };" — strip prefix.
            lhs, _, rhs = raw.partition("=")
            payload = rhs.strip().rstrip(";").strip()
            doc = json.loads(payload)
        except (OSError, ValueError, json.JSONDecodeError):
            return result

        services = doc.get("services", {}) or {}
        result["services"] = sorted(services.keys())
        for svc_name, svc in services.items():
            for fname, finding in (svc.get("findings", {}) or {}).items():
                level = (finding.get("level") or "info").lower()
                result["by_severity"][level] = result["by_severity"].get(level, 0) + 1
                items = finding.get("items", []) or []
                if not items:
                    continue
                result["findings"].append({
                    "service": svc_name,
                    "id": fname,
                    "level": level,
                    "description": finding.get("description", ""),
                    "rationale": finding.get("rationale", ""),
                    "affected_count": len(items),
                })
        return result

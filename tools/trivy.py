"""
Trivy wrapper — container image, IaC, and filesystem CVE scanner.

Trivy is a CNCF-graduated vulnerability scanner. We invoke it with
``--format json`` and parse the structured output rather than scraping
human-readable text. Supports three target shapes:

  * ``image``  – ``trivy image <ref>`` (default)
  * ``fs``     – ``trivy fs <path>``
  * ``config`` – ``trivy config <path>`` (IaC: Dockerfile, k8s, terraform)

Risk class: ``passive`` — Trivy reads remote registry/local files; no
traffic to the user-supplied ``target`` host beyond image-pull.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class TrivyTool(BaseTool):
    """Trivy vulnerability scanner wrapper."""

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "trivy"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("trivy", {})
        scan_type = kwargs.get("scan_type", cfg.get("scan_type", "image"))
        if scan_type not in ("image", "fs", "config"):
            scan_type = "image"

        severity = kwargs.get("severity", cfg.get("severity", "CRITICAL,HIGH,MEDIUM"))
        if isinstance(severity, list):
            severity = ",".join(s.upper() for s in severity)

        cmd: List[str] = ["trivy", scan_type, "--format", "json", "--quiet"]
        if severity:
            cmd.extend(["--severity", severity])
        if kwargs.get("ignore_unfixed", cfg.get("ignore_unfixed", False)):
            cmd.append("--ignore-unfixed")
        # Default to no-progress so output is one clean JSON blob.
        cmd.append("--no-progress")
        cmd.append(target)
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Flatten Trivy's nested ``Results[].Vulnerabilities[]`` shape.

        Returns one record per vulnerability with the fields downstream
        analysts care about. Falls back to empty result on malformed JSON
        rather than raising — partial scans should still produce a result
        dict the rest of the pipeline understands.
        """
        result: Dict[str, Any] = {
            "vulnerabilities": [],
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
            "artifact": "",
            "scan_type": "",
        }
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        result["artifact"] = doc.get("ArtifactName", "")
        result["scan_type"] = doc.get("ArtifactType", "")
        for r in doc.get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                sev = (v.get("Severity") or "UNKNOWN").upper()
                result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1
                result["vulnerabilities"].append({
                    "id": v.get("VulnerabilityID"),
                    "pkg": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "severity": sev,
                    "title": v.get("Title", ""),
                    "cvss": (v.get("CVSS") or {}).get("nvd", {}).get("V3Score"),
                    "primary_url": v.get("PrimaryURL", ""),
                })
        return result

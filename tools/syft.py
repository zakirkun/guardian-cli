"""
Syft wrapper — Software Bill of Materials (SBOM) generator.

Syft (Anchore) emits package inventory for container images, filesystems,
and tarballs. We use the SPDX-JSON output for downstream interop (Grype,
license scanners). Risk class: ``passive``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class SyftTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "syft"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("syft", {})
        fmt = kwargs.get("format", cfg.get("format", "syft-json"))
        # Syft accepts: dir:., file:./x.tar, registry.example.com/image:tag, etc.
        cmd = ["syft", target, "-o", fmt, "--quiet"]
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"packages": [], "package_count": 0, "source": ""}
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result

        result["source"] = (doc.get("source") or {}).get("target", "") or doc.get("source", "")
        for pkg in doc.get("artifacts", []) or []:
            result["packages"].append({
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "type": pkg.get("type"),
                "language": pkg.get("language"),
                "licenses": pkg.get("licenses", []),
            })
        result["package_count"] = len(result["packages"])
        return result

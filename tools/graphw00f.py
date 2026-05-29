"""
graphw00f wrapper — GraphQL fingerprinting and engine detection.

Detects the GraphQL implementation (Apollo, Hasura, Graphene, AWS AppSync,
etc.) which drives downstream attack-tree selection. Risk class: ``active``
— sends benign introspection probes; no payload injection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class Graphw00fTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Installed via pip; binary in PATH is "graphw00f" but on some
        # platforms it's invoked as a Python module — keep both options
        # available by overriding command construction.
        self.tool_name = "graphw00f"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("graphw00f", {})
        # graphw00f wants the URL — accept full URL or build from target.
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        cmd: List[str] = ["graphw00f", "-t", url, "-d"]  # -d = detect mode
        if kwargs.get("fingerprint", cfg.get("fingerprint", True)):
            cmd.append("-f")
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Extract engine name + endpoint from graphw00f's stdout.

        Output is human-formatted ASCII art + key/value lines. We grep for
        the canonical fields rather than trying to parse the banner.
        """
        result: Dict[str, Any] = {
            "engine": "unknown",
            "endpoint": "",
            "introspection_enabled": False,
            "raw_match": "",
        }
        for line in output.splitlines():
            line_strip = line.strip()
            m = re.search(r"Discovered GraphQL Engine:\s*\(?(?P<eng>[^\)]+)\)?", line_strip)
            if m:
                result["engine"] = m.group("eng").strip()
                continue
            m = re.search(r"Endpoint(?: URL)?:\s*(?P<url>https?://\S+)", line_strip)
            if m:
                result["endpoint"] = m.group("url").strip()
                continue
            if "Introspection" in line_strip and ("Enabled" in line_strip or "True" in line_strip):
                result["introspection_enabled"] = True
        return result

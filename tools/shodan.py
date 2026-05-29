"""
Shodan wrapper — passive recon via Shodan API.

Uses the official ``shodan`` CLI (``pip install shodan``). Requires
``SHODAN_API_KEY`` env var configured by the operator. Risk class:
``passive`` — only queries Shodan's database; never touches the target.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ShodanTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "shodan"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("shodan", {})
        # ``mode`` picks the subcommand:
        #   host    – ``shodan host <ip>``
        #   search  – ``shodan search "<query>"``
        # Defaults to host lookup; falls back to search if target isn't an IP.
        mode = kwargs.get("mode", cfg.get("mode", "host"))
        cmd: List[str] = ["shodan", mode]
        if mode == "host":
            cmd.append(target)
        elif mode == "search":
            limit = int(kwargs.get("limit", cfg.get("limit", 100)))
            fields = kwargs.get("fields", cfg.get("fields", "ip_str,port,org,hostnames"))
            cmd.extend(["--limit", str(limit), "--fields", fields, target])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Shodan CLI text output (no native JSON for ``host``).

        Extracts the canonical fields for downstream agents. ``search``
        mode emits CSV-style rows with ``--fields`` we requested.
        """
        result: Dict[str, Any] = {
            "ports": [],
            "hostnames": [],
            "org": "",
            "country": "",
            "rows": [],
        }
        for line in output.splitlines():
            l = line.strip()
            if l.startswith("Ports:"):
                ports = l.split(":", 1)[1]
                result["ports"] = [
                    int(p) for p in ports.replace(",", " ").split() if p.isdigit()
                ]
            elif l.startswith("Hostnames:"):
                hosts = l.split(":", 1)[1].strip()
                result["hostnames"] = [h.strip() for h in hosts.split(",") if h.strip()]
            elif l.startswith("Organization:"):
                result["org"] = l.split(":", 1)[1].strip()
            elif l.startswith("Country:"):
                result["country"] = l.split(":", 1)[1].strip()
            elif l and not l.startswith(("Hostnames", "Country", "Organization", "Ports", "City", "ISP")):
                # Search mode rows (whitespace-separated).
                parts = l.split()
                if parts and parts[0].count(".") == 3:  # IPv4 heuristic
                    result["rows"].append(parts)
        return result

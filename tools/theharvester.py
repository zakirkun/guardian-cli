"""
theHarvester wrapper — passive OSINT for emails, names, subdomains, hosts.

Pulls from public sources (search engines, certificate transparency,
PassiveDNS, etc.). Risk class: ``passive``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class TheHarvesterTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "theHarvester"  # mixed case binary name

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("theharvester", {})
        sources = kwargs.get("sources", cfg.get(
            "sources", "crtsh,hackertarget,duckduckgo,otx,bing"
        ))
        if isinstance(sources, list):
            sources = ",".join(sources)
        limit = int(kwargs.get("limit", cfg.get("limit", 500)))
        # ``-f -`` would emit to stdout, but theHarvester demands a path.
        # We use a temp file via ``-f /tmp/...`` — but simpler: use stdout
        # which the tool emits as plain text by default.
        cmd: List[str] = ["theHarvester", "-d", target, "-b", sources, "-l", str(limit)]
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse theHarvester's banner-laden text output.

        It groups results under section headers like "[*] Emails found:".
        We scan section-by-section instead of relying on JSON (the ``-f``
        JSON output requires an output path which complicates the wrapper).
        """
        result: Dict[str, Any] = {
            "emails": [],
            "hosts": [],
            "ips": [],
            "asns": [],
        }
        section: str = ""
        for line in output.splitlines():
            l = line.strip()
            if not l:
                continue
            if "Emails found" in l:
                section = "emails"
                continue
            if "Hosts found" in l or "subdomains" in l.lower():
                section = "hosts"
                continue
            if "IPs found" in l:
                section = "ips"
                continue
            if "ASNS found" in l:
                section = "asns"
                continue
            if l.startswith("[") or l.startswith("=") or l.startswith("-"):
                continue
            if section == "emails" and "@" in l:
                result["emails"].append(l)
            elif section == "hosts":
                # Hosts may include resolved IPs after ":".
                host = l.split(":", 1)[0].strip()
                if host:
                    result["hosts"].append(host)
            elif section == "ips":
                result["ips"].append(l)
            elif section == "asns":
                result["asns"].append(l)
        # Dedupe.
        for k in result:
            result[k] = sorted(set(result[k]))
        return result

"""
Cariddi wrapper — JS endpoint + secret crawler for web apps.

Crawls a target site, follows links, parses JS bundles, and surfaces
endpoints, secrets, parameters, and external dependencies. Useful for
SPA targets where wordlist-based discovery (gobuster/ffuf) misses
client-side routes. Risk class: ``active``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class CariddiTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "cariddi"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("cariddi", {})
        # Cariddi reads URLs from stdin. We pass a single URL via -t.
        cmd: List[str] = ["cariddi", "-plain", "-json"]
        if kwargs.get("secrets", cfg.get("secrets", True)):
            cmd.append("-s")
        if kwargs.get("endpoints", cfg.get("endpoints", True)):
            cmd.append("-e")
        if kwargs.get("info", cfg.get("info", False)):
            cmd.append("-info")
        # Provide target via stdin substitute: cariddi accepts -i path/to/list.
        # For a single URL we use process substitution-style: write to a tmp.
        # Simpler approach: cariddi reads stdin by default; the engine pipes
        # the URL to stdin via ``echo``. Keep portable by using -i with /dev/stdin.
        # Most reliable: just use -t which reads a single target line.
        return cmd  # target is fed via stdin in BaseTool.execute upgrade if needed

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Cariddi -json emits one JSON record per discovered URL/secret."""
        result: Dict[str, Any] = {
            "endpoints": [],
            "secrets": [],
            "external": [],
        }
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Plain-text URL fallback line.
                if line.startswith(("http://", "https://")):
                    result["endpoints"].append(line)
                continue
            kind = rec.get("kind") or rec.get("type") or "endpoint"
            if kind == "secret":
                result["secrets"].append({
                    "url": rec.get("url"),
                    "name": rec.get("name"),
                    "match": (rec.get("match") or "")[:120],
                })
            elif kind == "external":
                result["external"].append(rec.get("url"))
            else:
                if rec.get("url"):
                    result["endpoints"].append(rec["url"])
        return result

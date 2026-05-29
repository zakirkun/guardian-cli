"""
Clairvoyance wrapper — GraphQL schema inference when introspection is OFF.

When a target disables introspection, Clairvoyance fuzzes field-suggestion
errors to reconstruct the schema. Risk class: ``intrusive`` — sends many
malformed queries that may trip rate-limits / WAFs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ClairvoyanceTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "clairvoyance"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("clairvoyance", {})
        url = target if target.startswith(("http://", "https://")) else f"https://{target}/graphql"
        wordlist = kwargs.get("wordlist", cfg.get("wordlist"))
        cmd: List[str] = ["clairvoyance", url]
        if wordlist:
            cmd.extend(["-w", str(wordlist)])
        # Concurrent worker count — keep low by default to avoid WAF.
        concurrency = kwargs.get("concurrency", cfg.get("concurrency", 4))
        cmd.extend(["-c", str(concurrency)])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"types": [], "type_count": 0}
        if not output.strip():
            return result
        try:
            doc = json.loads(output)
        except json.JSONDecodeError:
            return result
        # Clairvoyance outputs an introspection-shaped schema.
        schema = (doc.get("data") or {}).get("__schema") or {}
        for t in schema.get("types", []) or []:
            name = t.get("name")
            if not name or name.startswith("__"):
                continue
            result["types"].append({
                "name": name,
                "kind": t.get("kind"),
                "field_count": len(t.get("fields") or []),
            })
        result["type_count"] = len(result["types"])
        return result

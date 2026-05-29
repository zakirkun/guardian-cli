"""
BloodHound data-collection wrapper.

Drives BloodHound.py (Python collector) against a domain controller.
Output is a ZIP of JSON files that load into the BloodHound GUI / cypher
queries. Risk class: ``intrusive`` — requires authenticated LDAP queries
and may trip account-lockout if credentials are invalid.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class BloodHoundTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # bloodhound-python ships as ``bloodhound-python``.
        self.tool_name = "bloodhound-python"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("bloodhound", {})
        out_dir = kwargs.get("out_dir") or tempfile.mkdtemp(prefix="bloodhound_")
        self._out_dir = Path(out_dir)

        cmd: List[str] = [
            "bloodhound-python",
            "-d", kwargs.get("domain", cfg.get("domain", target)),
            "-u", kwargs.get("username", cfg.get("username", "")),
            "-p", kwargs.get("password", cfg.get("password", "")),
            "-c", kwargs.get("collection", cfg.get("collection", "All")),
            "-ns", kwargs.get("nameserver", cfg.get("nameserver", target)),
            "--zip",
            "--output", str(self._out_dir),
        ]
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "users": 0,
            "computers": 0,
            "groups": 0,
            "domains": 0,
            "trusts": 0,
            "zip_path": "",
        }
        # Counts from collector status lines.
        import re
        for kind, key in [
            ("users", "users"),
            ("computers", "computers"),
            ("groups", "groups"),
            ("domains", "domains"),
            ("trusts", "trusts"),
        ]:
            m = re.search(rf"Found (\d+)\s+{key}", output, re.IGNORECASE)
            if m:
                result[kind] = int(m.group(1))

        zips = list(self._out_dir.glob("*.zip"))
        if zips:
            result["zip_path"] = str(zips[0])
        return result

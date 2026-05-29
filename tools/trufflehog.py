"""
TruffleHog wrapper — secrets scanning with verification.

TruffleHog v3 supports git/filesystem/docker/s3/etc. Default mode here
scans a filesystem path; ``--json`` emits one record per line. Risk
class: ``passive``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class TruffleHogTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "trufflehog"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("trufflehog", {})
        mode = kwargs.get("mode", cfg.get("mode", "filesystem"))
        cmd: List[str] = ["trufflehog", mode, target, "--json", "--no-update"]
        if kwargs.get("only_verified", cfg.get("only_verified", False)):
            cmd.append("--only-verified")
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        secrets: List[Dict[str, Any]] = []
        verified = 0
        unverified = 0
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            is_verified = rec.get("Verified", False)
            if is_verified:
                verified += 1
            else:
                unverified += 1
            secrets.append({
                "detector": rec.get("DetectorName"),
                "verified": is_verified,
                "raw": rec.get("Raw", "")[:120],  # don't full-quote secrets
                "source": (rec.get("SourceMetadata", {}) or {}).get("Data", {}),
            })
        return {
            "secrets": secrets,
            "secret_count": len(secrets),
            "verified": verified,
            "unverified": unverified,
        }

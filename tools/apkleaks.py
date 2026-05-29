"""
APKLeaks wrapper — secrets and endpoints in Android APK files.

Static-analyzes an APK, extracts hardcoded URIs, S3 bucket names, API
keys, JWT secrets. Risk class: ``passive``.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ApkLeaksTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "apkleaks"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        out_path = kwargs.get("out_path") or tempfile.mktemp(
            prefix="apkleaks_", suffix=".json"
        )
        self._out_path = Path(out_path)
        return [
            "apkleaks",
            "-f", target,
            "--json",
            "-o", str(self._out_path),
        ]

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"leaks": {}, "leak_count": 0}
        if not self._out_path.exists():
            return result
        try:
            doc = json.loads(self._out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return result

        # APKLeaks JSON: {"results": [{"name": "...", "matches": [...]}]}
        for entry in doc.get("results", []) or []:
            name = entry.get("name", "unknown")
            matches = entry.get("matches", []) or []
            result["leaks"][name] = matches[:50]
            result["leak_count"] += len(matches)
        return result

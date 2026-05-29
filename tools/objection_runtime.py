"""
Objection wrapper — Frida-based runtime mobile inspection.

Drives a connected device/emulator: dumps keychain, bypasses SSL pinning,
inspects loaded classes. Requires a frida-server running on the device
and ``objection`` installed on the host. Risk class: ``intrusive`` —
modifies process memory and may crash the target app.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ObjectionRuntimeTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "objection"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("objection", {})
        # ``target`` here is the Android package name (e.g. com.example.app).
        action = kwargs.get("action", cfg.get("action", "explore"))
        # Objection takes commands via ``-s`` for scripted runs.
        # We execute a one-shot script then exit.
        scripts = {
            "explore":      "android keystore list ; exit",
            "ssl_pin":      "android sslpinning disable ; exit",
            "root_detect":  "android root disable ; exit",
            "keychain":     "ios keychain dump ; exit",
            "permissions":  "android info permissions ; exit",
        }
        script = scripts.get(action, scripts["explore"])
        return [
            "objection",
            "-g", target,
            "explore",
            "-s", script,
        ]

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ssl_pinning_bypassed": "ssl pinning disabled" in output.lower()
                or "bypassed" in output.lower(),
            "keystore_entries": [],
            "permissions": [],
            "raw_excerpt": output[-1500:],
        }
        # Keystore dump rows.
        for m in re.finditer(r"alias:\s*(\S+)", output, re.IGNORECASE):
            result["keystore_entries"].append(m.group(1))
        # Permissions block.
        for m in re.finditer(r"^\s*android\.permission\.(\S+)", output, re.MULTILINE):
            result["permissions"].append(m.group(1))
        return result

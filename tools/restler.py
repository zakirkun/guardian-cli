"""
RESTler wrapper — Microsoft's stateful REST API fuzzer.

Generates request sequences from an OpenAPI/Swagger spec and discovers
state-dependent vulnerabilities (BOLA, BFLA, mass assignment).

The full RESTler workflow is multi-stage (compile, test, fuzz). We
support the ``test`` mode here as a sane default; ``fuzz`` mode runs
much longer and should be opted into via ``--mode fuzz`` from the
workflow YAML. Risk class: ``intrusive``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class RestlerTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Binary is "Restler" or "restler" depending on packaging; try lowercase.
        self.tool_name = "restler"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("restler", {})
        spec = kwargs.get("spec", cfg.get("spec", target))
        mode = kwargs.get("mode", cfg.get("mode", "test"))
        if mode not in ("test", "fuzz", "fuzz-lean"):
            mode = "test"
        # RESTler invocation differs from typical tools — driven by mode.
        cmd: List[str] = [
            "restler",
            mode,
            "--api_spec", spec,
            "--no_ssl",
        ]
        time_budget = float(kwargs.get("time_budget", cfg.get("time_budget", 0.5)))
        cmd.extend(["--time_budget", str(time_budget)])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """RESTler writes structured logs to ``Test/`` or ``Fuzz/`` dirs.

        We surface what we can from stdout — coverage stats and bug count.
        Full bug analysis requires reading the bug-bucket JSON files in
        the output directory, which is out-of-scope for this wrapper.
        """
        import re

        result: Dict[str, Any] = {
            "requests_sent": 0,
            "bugs_found": 0,
            "coverage": {},
            "summary": "",
        }
        for line in output.splitlines():
            m = re.search(r"Total requests sent:\s*(\d+)", line, re.IGNORECASE)
            if m:
                result["requests_sent"] = int(m.group(1))
                continue
            m = re.search(r"Total bugs found:\s*(\d+)", line, re.IGNORECASE)
            if m:
                result["bugs_found"] = int(m.group(1))
                continue
            m = re.search(r"Coverage:\s*(\d+)/(\d+)", line)
            if m:
                result["coverage"] = {
                    "covered": int(m.group(1)),
                    "total": int(m.group(2)),
                }
        # Last 500 chars as a summary tail.
        result["summary"] = output[-500:]
        return result

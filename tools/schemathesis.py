"""
Schemathesis wrapper — property-based fuzzing for OpenAPI / GraphQL.

Schemathesis ingests an OpenAPI spec URL or path, generates property-
based test cases, and runs them against the implementation. Output is
JUnit XML by default; we ask for ``--report=json`` plus a hooks-loaded
JSON sink. Risk class: ``intrusive`` — sends real requests with crafted
payloads against the spec.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class SchemathesisTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "schemathesis"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("schemathesis", {})
        # ``target`` here is the URL of the running API (or a local path
        # to the spec). The spec URL is a separate parameter.
        spec = kwargs.get("spec", cfg.get("spec", target))
        base_url = kwargs.get("base_url", target)

        cmd: List[str] = ["schemathesis", "run", spec, "--no-color"]
        if base_url and base_url != spec:
            cmd.extend(["--base-url", base_url])

        checks = kwargs.get("checks", cfg.get("checks", "all"))
        cmd.extend(["--checks", checks])

        workers = int(kwargs.get("workers", cfg.get("workers", 4)))
        cmd.extend(["--workers", str(workers)])

        # Bound the run — without limits these can fuzz forever.
        max_examples = int(kwargs.get("max_examples", cfg.get("max_examples", 50)))
        cmd.extend(["--hypothesis-max-examples", str(max_examples)])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Schemathesis CLI output is human-formatted with section headers.

        We extract the failure count + per-check counts from the summary
        block. JSON-mode output requires a hooks file; sticking with the
        text parser keeps the wrapper standalone.
        """
        result: Dict[str, Any] = {
            "passed": 0,
            "failed": 0,
            "errored": 0,
            "failures": [],
        }
        # Summary line: "FAILED: 3 failed, 12 passed in 14.21s"
        summary = re.search(
            r"FAILED:?\s+(\d+)\s+failed[,\s]+(\d+)\s+passed",
            output,
            re.IGNORECASE,
        ) or re.search(
            r"(\d+)\s+passed[,\s]+(\d+)\s+failed",
            output,
            re.IGNORECASE,
        )
        if summary:
            try:
                # Order of groups varies by output format; try both.
                if "failed" in summary.group(0).lower().split()[0]:
                    result["failed"] = int(summary.group(1))
                    result["passed"] = int(summary.group(2))
                else:
                    result["passed"] = int(summary.group(1))
                    result["failed"] = int(summary.group(2))
            except (IndexError, ValueError):
                pass

        # Failure blocks start with "_____ FAILED: <endpoint> _____".
        for m in re.finditer(
            r"_+\s+FAILED:?\s+(.+?)\s+_+", output, flags=re.MULTILINE
        ):
            result["failures"].append({"endpoint": m.group(1).strip()})

        return result

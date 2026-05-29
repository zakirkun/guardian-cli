"""
NVIDIA Garak wrapper — LLM vulnerability scanner.

Garak probes a target LLM for known weaknesses: prompt injection,
jailbreaks, data leakage, encoding tricks, etc. Output is JSONL by
default; we wire ``--report_prefix`` and parse the resulting hit log.

Risk class: ``intrusive`` — sends a lot of malicious prompts; will trip
moderation filters and rate limits.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class GarakTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "garak"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("garak", {})
        # ``target`` here is interpreted as the model identifier (e.g. an
        # OpenAI model name, a Hugging Face repo, an API endpoint URL).
        model_type = kwargs.get("model_type", cfg.get("model_type", "openai"))
        probes = kwargs.get("probes", cfg.get("probes", "all"))

        out_prefix = kwargs.get("out_prefix") or tempfile.mkdtemp(prefix="garak_")
        self._out_prefix = Path(out_prefix)

        cmd: List[str] = [
            "garak",
            "--model_type", model_type,
            "--model_name", target,
            "--probes", probes,
            "--report_prefix", str(self._out_prefix / "report"),
        ]
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "hits": [],
            "by_probe": {},
            "total_hits": 0,
        }
        # Garak writes ``<prefix>.report.jsonl`` and ``.hitlog.jsonl``.
        hitlog = self._out_prefix.parent / f"{self._out_prefix.name}.hitlog.jsonl"
        if not hitlog.exists():
            return result
        for line in hitlog.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            probe = rec.get("probe_classname") or rec.get("probe", "unknown")
            result["by_probe"][probe] = result["by_probe"].get(probe, 0) + 1
            result["hits"].append({
                "probe": probe,
                "detector": rec.get("detector"),
                "trigger": (rec.get("prompt") or "")[:200],
                "response": (rec.get("output") or "")[:200],
            })
        result["total_hits"] = len(result["hits"])
        return result

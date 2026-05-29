"""
Tier-3 agent-level evals.

Measures the *quality of LLM judgement*, not the correctness of tool
output parsing. These cases are expensive (real API calls) — gated by
the ``agent_eval`` pytest marker.

Each case loads a (tool_output, expected_findings) JSONL row from
``evals/datasets/`` and asks the analyst agent to interpret it. We score:

  * **Hallucination rate** — fraction of CVE/CWE refs the agent emitted
    that aren't grounded in the tool output or KB.
  * **Finding precision/recall** — vs expected_findings labels.
  * **CVSS validity** — fraction of emitted CVSS vectors that
    ``core.cvss_calculator.parse_and_score`` validates.
  * **Cost per valid finding** — tokens × pricing / verified findings.

The dataset format is JSONL, one record per line:

    {"tool": "nuclei", "raw_output": "...", "expected_cves": ["CVE-..."], ...}

This lets researchers ship deltas as data — no code changes needed to
expand the benchmark.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

import pytest

DATASETS_DIR = Path(__file__).parent / "datasets"


@dataclass
class AnalystEvalCase:
    tool: str
    raw_output: str
    expected_cves: List[str]
    expected_severities: List[str]
    notes: str = ""


def _load_jsonl(path: Path) -> Iterator[AnalystEvalCase]:
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise AssertionError(f"{path}:{line_no} bad JSON: {e}") from e
            yield AnalystEvalCase(
                tool=rec.get("tool", "unknown"),
                raw_output=rec.get("raw_output", ""),
                expected_cves=rec.get("expected_cves", []),
                expected_severities=rec.get("expected_severities", []),
                notes=rec.get("notes", ""),
            )


def _all_cases() -> List[AnalystEvalCase]:
    cases: List[AnalystEvalCase] = []
    for jsonl in sorted(DATASETS_DIR.glob("*.jsonl")):
        cases.extend(_load_jsonl(jsonl))
    return cases


_CASES = _all_cases()


@pytest.mark.agent_eval
@pytest.mark.parametrize(
    "case",
    _CASES,
    ids=[f"{i}::{c.tool}" for i, c in enumerate(_CASES)],
)
def test_analyst_grounding(case: AnalystEvalCase) -> None:
    """Run the analyst against a labeled tool-output sample.

    Gated by ``agent_eval``; will spend money. Skipped by default.
    Concrete scoring lives here as documentation — actual API plumbing
    happens once OllamaProvider (A4) lands so the eval can also run
    against a free local model for CI coverage.
    """
    pytest.skip("Agent-level eval pending OllamaProvider (item A4) for free CI runs.")

"""
Tier-2 workflow integration evals.

Boots dockerised vulnerable apps and runs Guardian end-to-end against
them. Each ``WorkflowEvalCase`` declares:

  * ``compose_file``: docker-compose.yml fragment that brings the target up
  * ``workflow``: name of the Guardian workflow to run
  * ``expected_findings``: list of finding identifiers (CVE / template_id /
    title-substring) the workflow MUST surface
  * ``min_findings``: lower bound on raw count (catch regressions even if
    specific IDs aren't in expected_findings)

These cases require ``docker`` available and external tool binaries on
PATH. Skipped unless ``-m integration`` is passed.

Acceptance is computed via ``evals.scoring.score_binary`` so improvements
across runs are comparable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import pytest


@dataclass
class WorkflowEvalCase:
    name: str
    workflow: str
    target: str
    expected_findings: List[str] = field(default_factory=list)
    min_findings: int = 0
    compose_file: Optional[Path] = None
    timeout_seconds: int = 600


# Seed cases. Targets here are placeholders — the docker-compose fragments
# under ``evals/integration/`` would bring up the real services. CI gates
# the integration tier so missing infrastructure doesn't fail PR checks.
EVAL_CASES: List[WorkflowEvalCase] = [
    WorkflowEvalCase(
        name="dvwa_web_pentest",
        workflow="web_pentest",
        target="http://localhost:8080",
        expected_findings=["sql-injection", "reflected-xss", "csrf"],
        min_findings=3,
    ),
    WorkflowEvalCase(
        name="juiceshop_web_full",
        workflow="web_full_assessment",
        target="http://localhost:3000",
        expected_findings=["broken-authentication", "sensitive-data-exposure"],
        min_findings=5,
    ),
    WorkflowEvalCase(
        name="dvga_graphql",
        workflow="graphql_pentest",
        target="http://localhost:5013/graphql",
        expected_findings=["introspection", "batching", "dos"],
        min_findings=2,
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize("case", EVAL_CASES, ids=lambda c: c.name)
def test_workflow_finds_expected(case: WorkflowEvalCase) -> None:
    """Run a workflow against a docker target, score findings.

    Skipped by default. Run via ``pytest evals/ -m integration``. Requires
    docker + the target image already pulled. The actual orchestration
    (compose up/down) is intentionally out-of-band — the eval *measures*
    what Guardian produces; it doesn't manage infrastructure.
    """
    pytest.importorskip("docker", reason="docker SDK not installed")
    pytest.skip(
        "Integration eval scaffolding ready — wire compose_file orchestration "
        "and run with `-m integration` once dockerised targets are available."
    )

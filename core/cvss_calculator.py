"""
CVSS v3.1 vector parser + score recomputation.

Why this exists:
The reporter LLM emits CVSS vectors as part of every finding (per
``ai/prompt_templates/reporter.py``). Without validation those scores ship
to the client report verbatim — plausible-looking but uncomputed numbers.
This module parses the vector string per CVSS v3.1 spec, recomputes the
base score, and either:

  * confirms the LLM-emitted score matches (within 0.1 tolerance), or
  * overwrites with the recomputed score and flags the finding's
    ``cvss_score_unverified`` field.

We embed the v3.1 base equations directly rather than vendor a 3rd-party
library to keep guardian's deps minimal — the math is fixed and small.
References: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# Metric weights from CVSS v3.1 spec table (§8.1).
_WEIGHTS: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # PR weights when scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},   # PR weights when scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.0, "L": 0.22, "H": 0.56},
}
_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/")


@dataclass
class CvssResult:
    """Outcome of a CVSS vector validation."""

    vector: str
    base_score: float
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | NONE
    valid: bool
    error: Optional[str] = None


def parse_and_score(vector: str) -> CvssResult:
    """Parse a CVSS v3.x vector and return the recomputed base score.

    Returns ``valid=False`` on any parsing error with ``error`` set; the
    caller can then decide to drop the score or flag the finding. Never
    raises — bad input is a data problem, not a programmer error.
    """
    if not isinstance(vector, str) or not vector:
        return CvssResult(vector="", base_score=0.0, severity="NONE",
                          valid=False, error="empty vector")
    v = vector.strip()
    if not _VECTOR_RE.match(v):
        return CvssResult(vector=v, base_score=0.0, severity="NONE",
                          valid=False, error="missing CVSS:3.x prefix")

    try:
        metrics = _parse_metrics(v)
        score = _base_score(metrics)
    except ValueError as e:
        return CvssResult(vector=v, base_score=0.0, severity="NONE",
                          valid=False, error=str(e))

    return CvssResult(
        vector=v,
        base_score=score,
        severity=_severity_band(score),
        valid=True,
    )


def validate_against_claimed(
    vector: str,
    claimed_score: Optional[float],
    tolerance: float = 0.11,
) -> Tuple[CvssResult, bool]:
    """Compare an LLM-claimed score against the recomputed value.

    Returns ``(result, matches)``. ``matches`` is True when the claimed
    score is within ``tolerance`` of the recomputed score, or when no
    claim was made (None — then any recomputed score is accepted).
    """
    result = parse_and_score(vector)
    if not result.valid:
        return result, False
    if claimed_score is None:
        return result, True
    return result, abs(result.base_score - claimed_score) <= tolerance


# ── Internals ────────────────────────────────────────────────────────────────


def _parse_metrics(vector: str) -> Dict[str, str]:
    """Split a vector into its metric key/value pairs.

    Tolerates extra temporal/environmental metrics by ignoring them — only
    the eight base metrics are required. Raises ``ValueError`` on missing
    base metrics or unknown values.
    """
    body = vector.split("/", 1)[1]
    parts = body.split("/")
    metrics: Dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            raise ValueError(f"malformed metric token: {p}")
        k, v = p.split(":", 1)
        metrics[k] = v

    for key in _REQUIRED_METRICS:
        if key not in metrics:
            raise ValueError(f"missing required metric: {key}")

    if metrics["S"] not in ("U", "C"):
        raise ValueError(f"invalid Scope value: {metrics['S']}")
    return metrics


def _base_score(m: Dict[str, str]) -> float:
    """CVSS v3.1 base-score formula. Returns 0.0..10.0 rounded up to 0.1."""
    av = _W("AV", m["AV"])
    ac = _W("AC", m["AC"])
    ui = _W("UI", m["UI"])
    pr_table = _WEIGHTS["PR_C"] if m["S"] == "C" else _WEIGHTS["PR_U"]
    pr = _lookup(pr_table, m["PR"], "PR")
    c, i, a = _W("C", m["C"]), _W("I", m["I"]), _W("A", m["A"])

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if m["S"] == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    return _roundup(base)


def _W(category: str, value: str) -> float:
    return _lookup(_WEIGHTS[category], value, category)


def _lookup(table: Dict[str, float], value: str, category: str) -> float:
    if value not in table:
        raise ValueError(f"invalid {category} value: {value}")
    return table[value]


def _roundup(score: float) -> float:
    """CVSS spec round-up: ceiling to nearest 0.1."""
    return math.ceil(score * 10) / 10


def _severity_band(score: float) -> str:
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"

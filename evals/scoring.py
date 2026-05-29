"""Scoring primitives for Guardian agent evals.

Reused across A1 (KB grounding), A2 (debate triage), A5 (tool ranker),
A7 (judge routing). Each scorer returns a dataclass instance — never
prints — so callers can aggregate, JSON-serialise, or feed back into
metric tracking systems.

These are intentionally simple. The purpose is *consistency* across
evals, not state-of-the-art metric implementations. If we need more,
swap in scikit-learn / ranx later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Set


@dataclass
class BinaryClassificationScore:
    """Standard precision / recall / F1 for finding-level evals."""

    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0


@dataclass
class HallucinationScore:
    """Tracks fabricated CVE / CWE references in agent output."""

    total_refs: int
    grounded_refs: int  # found in the KB or tool output
    hallucinated_refs: int

    @property
    def hallucination_rate(self) -> float:
        return self.hallucinated_refs / self.total_refs if self.total_refs else 0.0

    @property
    def grounding_rate(self) -> float:
        return self.grounded_refs / self.total_refs if self.total_refs else 0.0


@dataclass
class CostEfficiencyScore:
    """Cost per validated finding — primary metric for A7 judge routing."""

    total_cost_usd: float
    valid_findings: int

    @property
    def cost_per_finding(self) -> float:
        return self.total_cost_usd / self.valid_findings if self.valid_findings else float("inf")


@dataclass
class RankingScore:
    """For A5 tool-ranker eval. Compares ranker top-k vs actual best tool."""

    top1_correct: int
    top3_correct: int
    total: int
    rankings: List[List[str]] = field(default_factory=list)

    @property
    def top1_accuracy(self) -> float:
        return self.top1_correct / self.total if self.total else 0.0

    @property
    def top3_accuracy(self) -> float:
        return self.top3_correct / self.total if self.total else 0.0


# ── Scorers ──────────────────────────────────────────────────────────────────


def score_binary(
    predicted: Iterable[str],
    expected: Iterable[str],
) -> BinaryClassificationScore:
    """Score a finding-id list against a ground-truth list.

    Identifier semantics are caller-defined — typically a CVE ID, a
    finding-title hash, or a (tool, vuln_id) tuple. Order is irrelevant;
    duplicates are deduped.
    """
    pred = set(predicted)
    exp = set(expected)
    return BinaryClassificationScore(
        true_positives=len(pred & exp),
        false_positives=len(pred - exp),
        false_negatives=len(exp - pred),
    )


def score_hallucinations(
    refs: Iterable[str],
    grounded_set: Set[str],
) -> HallucinationScore:
    """Score CVE/CWE/CVE refs against a grounding set (KB or tool output)."""
    refs_list = list(refs)
    grounded = sum(1 for r in refs_list if r in grounded_set)
    return HallucinationScore(
        total_refs=len(refs_list),
        grounded_refs=grounded,
        hallucinated_refs=len(refs_list) - grounded,
    )


def score_cost(
    total_cost_usd: float,
    valid_findings: int,
) -> CostEfficiencyScore:
    return CostEfficiencyScore(
        total_cost_usd=total_cost_usd,
        valid_findings=valid_findings,
    )

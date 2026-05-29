"""Tests for evals.scoring primitives."""

from __future__ import annotations

from evals.scoring import (
    BinaryClassificationScore,
    score_binary,
    score_cost,
    score_hallucinations,
)


class TestBinaryClassification:
    def test_perfect_match(self) -> None:
        s = score_binary(["a", "b"], ["a", "b"])
        assert s.precision == 1.0
        assert s.recall == 1.0
        assert s.f1 == 1.0

    def test_partial(self) -> None:
        # predicted: a,b,c   expected: a,b,d   →   tp=2, fp=1, fn=1
        s = score_binary(["a", "b", "c"], ["a", "b", "d"])
        assert s.true_positives == 2
        assert s.false_positives == 1
        assert s.false_negatives == 1
        assert abs(s.precision - 2 / 3) < 1e-9
        assert abs(s.recall - 2 / 3) < 1e-9

    def test_empty(self) -> None:
        s = score_binary([], [])
        assert s.precision == 0.0
        assert s.recall == 0.0
        assert s.f1 == 0.0

    def test_dedup(self) -> None:
        # Duplicates in either side must not inflate scores.
        s = score_binary(["a", "a", "b"], ["a", "b", "b"])
        assert s.true_positives == 2
        assert s.false_positives == 0
        assert s.false_negatives == 0


class TestHallucinations:
    def test_all_grounded(self) -> None:
        s = score_hallucinations(["CVE-1", "CVE-2"], {"CVE-1", "CVE-2", "CVE-3"})
        assert s.hallucination_rate == 0.0
        assert s.grounding_rate == 1.0

    def test_partial(self) -> None:
        s = score_hallucinations(["CVE-1", "CVE-99"], {"CVE-1"})
        assert s.hallucinated_refs == 1
        assert s.grounded_refs == 1
        assert s.hallucination_rate == 0.5

    def test_empty_safe(self) -> None:
        s = score_hallucinations([], {"CVE-1"})
        assert s.hallucination_rate == 0.0
        assert s.grounding_rate == 0.0


class TestCost:
    def test_basic(self) -> None:
        s = score_cost(total_cost_usd=1.0, valid_findings=4)
        assert s.cost_per_finding == 0.25

    def test_zero_findings_infinity(self) -> None:
        s = score_cost(total_cost_usd=1.0, valid_findings=0)
        assert s.cost_per_finding == float("inf")

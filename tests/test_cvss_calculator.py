"""Tests for core.cvss_calculator — vector parsing + base-score recomputation."""

from __future__ import annotations

import pytest

from core.cvss_calculator import parse_and_score, validate_against_claimed


# Reference vectors and scores from FIRST.org CVSS v3.1 examples + NVD.
REFERENCE_VECTORS = [
    # (vector, expected_score, expected_severity)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.9, "LOW"),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),  # 3.0 still valid
]


@pytest.mark.parametrize("vector,score,severity", REFERENCE_VECTORS)
def test_reference_vectors(vector: str, score: float, severity: str) -> None:
    r = parse_and_score(vector)
    assert r.valid, f"{vector} should parse"
    # Allow ±0.1 due to rounding direction differences across publishers.
    assert abs(r.base_score - score) <= 0.1, (
        f"{vector}: got {r.base_score}, expected {score}"
    )
    assert r.severity == severity


class TestInvalidVectors:
    def test_empty(self) -> None:
        r = parse_and_score("")
        assert r.valid is False

    def test_missing_prefix(self) -> None:
        r = parse_and_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r.valid is False
        assert r.error and "prefix" in r.error.lower()

    def test_missing_required_metric(self) -> None:
        r = parse_and_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # no A
        assert r.valid is False

    def test_invalid_metric_value(self) -> None:
        r = parse_and_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r.valid is False

    def test_invalid_scope(self) -> None:
        r = parse_and_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H")
        assert r.valid is False

    def test_non_string(self) -> None:
        r = parse_and_score(None)  # type: ignore[arg-type]
        assert r.valid is False


class TestValidateAgainstClaimed:
    def test_match(self) -> None:
        _, ok = validate_against_claimed(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
        )
        assert ok is True

    def test_within_tolerance(self) -> None:
        _, ok = validate_against_claimed(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.7
        )
        assert ok is True  # 0.1 tolerance

    def test_outside_tolerance(self) -> None:
        _, ok = validate_against_claimed(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 7.0
        )
        assert ok is False

    def test_no_claim(self) -> None:
        _, ok = validate_against_claimed(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None
        )
        assert ok is True

    def test_invalid_vector_never_matches(self) -> None:
        _, ok = validate_against_claimed("not-a-vector", 9.8)
        assert ok is False

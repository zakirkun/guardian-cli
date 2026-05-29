"""Tests for SARIF + DefectDojo + Slack exporters."""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from core.exporters import defectdojo, sarif, slack
from core.memory import Finding, PentestMemory


def _finding(**kwargs: Any) -> Finding:
    base: Dict[str, Any] = {
        "id": "f-1",
        "severity": "high",
        "title": "SQL Injection in /login",
        "description": "Stacked-query injection in username param",
        "evidence": "username=admin' UNION SELECT 1--",
        "tool": "sqlmap",
        "target": "https://app.example.com/login",
        "timestamp": "2026-05-28T00:00:00",
        "cwe": "CWE-89",
        "cve": "CVE-2024-1234",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "execution_id": "exec-42",
        "remediation": "Use parameterized queries",
    }
    base.update(kwargs)
    return Finding(**base)


@pytest.fixture
def populated_memory() -> PentestMemory:
    mem = PentestMemory("app.example.com", session_id="test-123")
    mem.add_finding(_finding())
    mem.add_finding(_finding(
        id="f-2", severity="medium", title="Reflected XSS",
        cwe="CWE-79", cve=None, cvss_score=6.1,
    ))
    # FP — must be excluded from all exporters.
    fp = _finding(id="f-3", title="False Positive Banner")
    fp.false_positive = True
    mem.add_finding(fp)
    return mem


class TestSarif:
    def test_basic_shape(self, populated_memory: PentestMemory) -> None:
        doc = sarif.export(populated_memory)
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1

        run = doc["runs"][0]
        # FP excluded — only 2 results.
        assert len(run["results"]) == 2
        assert run["tool"]["driver"]["name"] == "guardian"

    def test_severity_mapping(self, populated_memory: PentestMemory) -> None:
        doc = sarif.export(populated_memory)
        levels = sorted(r["level"] for r in doc["runs"][0]["results"])
        # high → error, medium → warning
        assert levels == ["error", "warning"]

    def test_security_severity_decimal(
        self, populated_memory: PentestMemory
    ) -> None:
        doc = sarif.export(populated_memory)
        critical = next(
            r for r in doc["runs"][0]["results"] if r["level"] == "error"
        )
        # GitHub code-scanning convention.
        assert critical["properties"]["security-severity"] == "9.8"

    def test_fingerprint_for_dedup(self, populated_memory: PentestMemory) -> None:
        doc = sarif.export(populated_memory)
        for r in doc["runs"][0]["results"]:
            assert "fingerprints" in r
            assert "guardian/execution/v1" in r["fingerprints"]

    def test_help_uri_for_cwe(self, populated_memory: PentestMemory) -> None:
        doc = sarif.export(populated_memory)
        # XSS finding has CWE but no CVE → help URI must point at MITRE CWE.
        for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
            if rule["id"] == "CWE-79":
                assert "cwe.mitre.org" in rule["helpUri"]
                return
        pytest.fail("CWE-79 rule not found in SARIF output")

    def test_serializable(self, populated_memory: PentestMemory) -> None:
        # Round-trip JSON to catch any non-serializable values.
        doc = sarif.export(populated_memory)
        s = json.dumps(doc)
        assert json.loads(s) == doc

    def test_empty_memory_safe(self) -> None:
        doc = sarif.export(PentestMemory("nothing.example.com"))
        assert doc["runs"][0]["results"] == []


class TestDefectDojo:
    def test_excludes_false_positives(self, populated_memory: PentestMemory) -> None:
        out = defectdojo.export(populated_memory)
        assert len(out["findings"]) == 2

    def test_severity_titlecased(self, populated_memory: PentestMemory) -> None:
        out = defectdojo.export(populated_memory)
        severities = {f["severity"] for f in out["findings"]}
        assert severities <= {"Critical", "High", "Medium", "Low", "Info"}

    def test_cwe_as_int(self, populated_memory: PentestMemory) -> None:
        out = defectdojo.export(populated_memory)
        cwes = [f.get("cwe") for f in out["findings"]]
        assert 89 in cwes  # CWE-89 → 89

    def test_evidence_in_description(self, populated_memory: PentestMemory) -> None:
        out = defectdojo.export(populated_memory)
        for f in out["findings"]:
            if f["title"].startswith("SQL Injection"):
                assert "username=admin" in f["description"]


class TestSlack:
    def test_payload_text_field(self, populated_memory: PentestMemory) -> None:
        p = slack.build_payload(populated_memory)
        assert "text" in p
        assert "test-123" in p["text"]

    def test_severity_summary_in_text(self, populated_memory: PentestMemory) -> None:
        p = slack.build_payload(populated_memory)
        text = p["text"]
        # 1 high + 1 medium (FP excluded? slack uses raw summary including FP).
        # Our build_payload reads memory.get_findings_summary() which excludes FPs.
        assert "high" in text
        assert "medium" in text

    def test_empty_memory_safe(self) -> None:
        p = slack.build_payload(PentestMemory("nothing.example.com"))
        assert "No findings" in p["text"]

    def test_top_n_truncation(self, populated_memory: PentestMemory) -> None:
        p = slack.build_payload(populated_memory, top_n=1)
        # Only one bullet in top-findings section.
        assert p["text"].count("\n  • [") == 1

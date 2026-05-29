"""
SARIF v2.1.0 exporter for Guardian findings.

SARIF (Static Analysis Results Interchange Format) is the lingua franca
for SAST/DAST output ingestion in GitHub code-scanning, Azure DevOps,
GitLab, DefectDojo, and most CI consumers. v2.1.0 schema reference:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

Mapping:
  PentestMemory.findings  →  runs[0].results[]
  Finding.tool            →  driver.name + tool fingerprint
  Finding.severity        →  result.level (error|warning|note)
  Finding.cvss_score      →  result.properties.security_severity (GitHub uses this)
  Finding.cwe             →  result.properties.cwe + taxonomies reference
  Finding.evidence        →  result.message.text + locations[].artifactLocation
  Finding.target          →  artifactLocation.uri
  Finding.execution_id    →  result.fingerprints["guardian/execution"]

Severity translation follows the convention in the SARIF spec annex:
  critical/high  → error
  medium         → warning
  low/info       → note

Returns the SARIF document as a Python dict; callers serialise to JSON.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from core.memory import Finding, PentestMemory


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_VERSION = "2.1.0"
_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
)


def export(memory: PentestMemory, *, tool_name: str = "guardian") -> Dict[str, Any]:
    """Build a SARIF v2.1.0 document from session memory.

    The result is a plain dict — callers ``json.dumps`` it. Validates
    enough structure that ``sarif-tools validate`` will accept it; not
    every optional SARIF field is populated (rules registry, taxonomies,
    invocations) but the required ones are.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in memory.findings:
        if f.false_positive:
            continue
        rule_id = _rule_id_for(f)
        if rule_id not in rules:
            rules[rule_id] = _rule_descriptor(f, rule_id)
        results.append(_finding_to_result(f, rule_id))

    invocation = {
        "executionSuccessful": True,
        "startTimeUtc": memory.start_time,
        "endTimeUtc": datetime.utcnow().isoformat() + "Z",
    }

    return {
        "$schema": _SCHEMA_URI,
        "version": _VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/zakirkun/guardian-cli",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "session_id": memory.session_id,
                    "target": memory.target,
                    "phase": memory.current_phase,
                },
            }
        ],
    }


# ── Internals ────────────────────────────────────────────────────────────────


def _rule_id_for(f: Finding) -> str:
    """Stable rule ID per (tool, cwe, cve, title) tuple.

    SARIF requires a ruleId on every result. We prefer CWE > CVE > tool
    plus a slugified title so the same vuln class collapses to one rule.
    """
    if f.cwe:
        return f.cwe
    if f.cve:
        return f.cve
    safe_title = "".join(c if c.isalnum() else "-" for c in (f.title or "finding")).strip("-")[:64]
    return f"{f.tool}/{safe_title or 'finding'}"


def _rule_descriptor(f: Finding, rule_id: str) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "name": (f.title or rule_id)[:120],
        "shortDescription": {"text": (f.title or rule_id)[:200]},
        "fullDescription": {"text": (f.description or f.title or rule_id)[:1000]},
        "helpUri": _help_uri_for(f),
        "properties": _rule_properties(f),
    }


def _help_uri_for(f: Finding) -> str:
    if f.cve:
        return f"https://nvd.nist.gov/vuln/detail/{f.cve}"
    if f.cwe and f.cwe.upper().startswith("CWE-"):
        return f"https://cwe.mitre.org/data/definitions/{f.cwe[4:]}.html"
    return "https://github.com/zakirkun/guardian-cli"


def _rule_properties(f: Finding) -> Dict[str, Any]:
    props: Dict[str, Any] = {
        "tool": f.tool,
    }
    tags: List[str] = []
    if f.cwe:
        tags.append(f.cwe)
    if f.owasp:
        tags.append(f.owasp)
        props["owasp"] = f.owasp
    if f.mitre_technique:
        tags.append(f.mitre_technique)
    if tags:
        props["tags"] = tags
    return props


def _finding_to_result(f: Finding, rule_id: str) -> Dict[str, Any]:
    level = _SEVERITY_TO_LEVEL.get((f.severity or "info").lower(), "note")
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": (f.description or f.title or rule_id)[:2000]
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target or ""},
                }
            }
        ],
        "properties": {
            "tool": f.tool,
            "severity": (f.severity or "info").lower(),
        },
    }

    # GitHub code-scanning honours `security-severity` (decimal CVSS-like).
    if f.cvss_score is not None:
        result["properties"]["security-severity"] = f"{f.cvss_score:.1f}"
    if f.cvss_vector:
        result["properties"]["cvss_vector"] = f.cvss_vector
    if f.cve:
        result["properties"]["cve"] = f.cve
    if f.evidence:
        result["properties"]["evidence"] = f.evidence[:1000]

    if f.execution_id:
        # SARIF fingerprints are a versioned key/value map. v/1 lets
        # consumers diff identical findings across runs without dupes.
        result["fingerprints"] = {"guardian/execution/v1": f.execution_id}

    return result

"""
DefectDojo exporter.

DefectDojo's Generic Findings Import schema is a JSON document with a
``findings`` array. Each finding has a fixed shape; the importer creates
or updates entries in an existing engagement / test on import.

API reference: https://documentation.defectdojo.com/integrations/parsers/file/generic/

This exporter only produces the JSON document. Pushing it to a running
DefectDojo instance is left to ``cli/commands/report.py`` so credentials
and engagement IDs aren't tangled into pure data translation.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.memory import Finding, PentestMemory


_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def export(memory: PentestMemory) -> Dict[str, Any]:
    """Return a Generic Findings Import-compatible JSON dict."""
    return {
        "findings": [_finding_to_dd(f) for f in memory.findings if not f.false_positive],
    }


def _finding_to_dd(f: Finding) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "title": f.title or "Untitled finding",
        "description": _build_description(f),
        "severity": _SEVERITY_MAP.get((f.severity or "info").lower(), "Info"),
        "active": True,
        "verified": False,
        "false_p": bool(f.false_positive),
        "mitigation": f.remediation or "",
        "tool": f.tool,
        "static_finding": False,
        "dynamic_finding": True,
    }
    if f.cve:
        out["cve"] = f.cve
    if f.cvss_score is not None:
        out["cvssv3_score"] = f.cvss_score
    if f.cvss_vector:
        out["cvssv3"] = f.cvss_vector
    if f.cwe and f.cwe.upper().startswith("CWE-") and f.cwe[4:].isdigit():
        out["cwe"] = int(f.cwe[4:])
    if f.target:
        out["url"] = f.target
    return out


def _build_description(f: Finding) -> str:
    parts = []
    if f.description:
        parts.append(f.description)
    if f.evidence:
        parts.append("\n## Evidence\n" + f.evidence[:2000])
    if f.execution_id:
        parts.append(f"\n## Execution ID\n{f.execution_id}")
    return "\n\n".join(parts) or f.title or ""

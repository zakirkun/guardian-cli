"""
Pydantic schemas for agent decisions and findings.

Replaces the brittle string-parsers in `core/planner.py:_parse_decision`,
`core/analyst_agent.py:_parse_findings`, and `core/tool_agent.py:_parse_selection`.
Every agent that produces structured output validates against one of these
models — anything that doesn't conform is rejected, not silently coerced.

Wiring contract:
  * Agents pass ``response_model=<Schema>`` to ``BaseProvider.generate_with_usage``.
  * Provider invokes JSON-mode (OpenAI ``response_format``, Anthropic tool use,
    Gemini structured output) and parses the response with this module.
  * On validation failure, ``parse_or_none`` returns ``None`` so the caller
    can retry once with a stricter prompt before giving up.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Type, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator


Severity = Literal["critical", "high", "medium", "low", "info"]
Phase = Literal["reconnaissance", "scanning", "analysis", "reporting"]
Recommendation = Literal["KEEP", "DISCARD", "VERIFY_MANUALLY"]


# Whitelist of action names the planner may emit. Sourced from
# core/planner.py:_known_actions — keep these in sync.
KNOWN_ACTIONS: frozenset = frozenset({
    "subdomain_enumeration", "dns_enumeration", "technology_detection",
    "port_scanning", "service_detection", "vulnerability_scanning",
    "web_probing", "ssl_analysis", "correlate_findings", "risk_assessment",
    "false_positive_filter", "prioritize_vulns", "generate_report",
    "executive_summary", "remediation_plan",
    "done", "complete", "finish", "stop",
})


# Whitelist of registered tool names. Pulled from core/tool_agent.TOOL_REGISTRY
# at import time so the source of truth stays in one place.
def _tool_names() -> frozenset:
    try:
        from core.tool_agent import TOOL_REGISTRY
        return frozenset(TOOL_REGISTRY)
    except ImportError:
        # During isolated test imports the core module may not be wired yet.
        return frozenset()


class PlannerDecision(BaseModel):
    """Output schema for ``PlannerAgent.decide_next_action``."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    next_action: str = Field(..., min_length=1, max_length=64)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    expected_outcome: str = Field(default="", max_length=400)
    reasoning: str = Field(default="", max_length=4000)
    mitre_technique: Optional[str] = Field(default=None, max_length=16)
    phase_transition: Optional[Phase] = None

    @field_validator("next_action")
    @classmethod
    def _whitelist_action(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if cleaned not in KNOWN_ACTIONS:
            raise ValueError(
                f"Unknown action '{cleaned}' (must be one of {sorted(KNOWN_ACTIONS)})"
            )
        return cleaned


class ToolSelection(BaseModel):
    """Output schema for ``ToolAgent.execute`` (which tool to run)."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    tool: str = Field(..., min_length=1, max_length=32)
    arguments: str = Field(default="", max_length=400)
    expected_output: str = Field(default="", max_length=400)
    reasoning: str = Field(default="", max_length=2000)

    @field_validator("tool")
    @classmethod
    def _whitelist_tool(cls, v: str) -> str:
        cleaned = v.strip().lower()
        names = _tool_names()
        if names and cleaned not in names:
            raise ValueError(f"Unknown tool '{cleaned}' (not in TOOL_REGISTRY)")
        return cleaned


class FindingModel(BaseModel):
    """Per-finding schema emitted by ``AnalystAgent.interpret_output``."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    severity: Severity
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    evidence: str = Field(default="", max_length=2000)
    impact: str = Field(default="", max_length=1000)
    remediation: str = Field(default="", max_length=1000)
    cwe: Optional[str] = Field(default=None, max_length=16)
    cve: Optional[str] = Field(default=None, max_length=20)
    owasp: Optional[str] = Field(default=None, max_length=64)
    cvss_vector: Optional[str] = Field(default=None, max_length=128)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    mitre_technique: Optional[str] = Field(default=None, max_length=16)
    false_positive_probability: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip().lower()
        return v


class AnalysisResult(BaseModel):
    """Aggregate schema returned by the analyst agent for a single tool run."""

    model_config = ConfigDict(extra="ignore")

    findings: List[FindingModel] = Field(default_factory=list)
    summary: str = Field(default="", max_length=2000)
    missed_checks: str = Field(default="", max_length=1000)


class FalsePositiveVerdict(BaseModel):
    """Schema for the false-positive evaluation prompt."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    confidence: int = Field(..., ge=0, le=100)
    analysis: str = Field(default="", max_length=2000)
    recommendation: Recommendation = "VERIFY_MANUALLY"
    verification_steps: str = Field(default="", max_length=1000)


# ── Helpers ──────────────────────────────────────────────────────────────────

T = TypeVar("T", bound=BaseModel)


def parse_or_none(payload: Any, model: Type[T]) -> Optional[T]:
    """Return a validated ``model`` instance, or ``None`` if invalid.

    ``payload`` may be a dict, a JSON string, or already a ``model``
    instance. Logs nothing — callers decide how to surface failures.
    """
    if payload is None:
        return None
    if isinstance(payload, model):
        return payload
    try:
        if isinstance(payload, str):
            return model.model_validate_json(payload)
        if isinstance(payload, dict):
            return model.model_validate(payload)
    except Exception:
        return None
    return None


def schema_for_prompt(model: Type[BaseModel]) -> Dict[str, Any]:
    """Return a JSON schema suitable for OpenAI ``response_format`` / Gemini
    ``response_schema`` / Anthropic tool use ``input_schema``.

    Strips Pydantic internals that providers reject (``$defs``, ``title`` on
    nested objects sometimes confuses Vertex AI).
    """
    schema = model.model_json_schema()
    schema.pop("title", None)
    return schema

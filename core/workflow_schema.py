"""
Workflow DSL v2 — schema, validator, and DAG compiler.

v1 schema was a flat list of steps executed sequentially. v2 adds:
  * ``id`` on every step (required) — referenced by ``depends_on`` and as the
    namespace key for variable interpolation (``{{ <id>.parsed.<key> }}``).
  * ``depends_on: [id, ...]`` — declares a step's prerequisites. The engine
    runs independent steps in parallel up to ``max_parallel_tools``.
  * ``when: "<jinja-expr>"`` — Jinja2 expression evaluated in a sandboxed
    environment against prior step results. Falsy ⇒ skip.
  * ``parameters: {key: "{{ <id>.parsed.alive_hosts }}"}`` — Jinja2 template
    string. Resolved against prior results before execution.

This module is compiler + DSL. Execution lives in ``core.workflow``.

The compiler enforces:
  * Step IDs are unique, valid identifiers.
  * Every ``depends_on`` reference exists.
  * The graph is acyclic (Kahn's algorithm — sort fails on cycle).
  * Jinja2 templates use the sandboxed environment (no filesystem/network).

v1 documents are still accepted (auto-detected when ``version`` ≠ 2 and no
step has an ``id`` field) and converted into v2 form internally with a
deprecation warning. Existing workflows keep working through one release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from jinja2 import StrictUndefined
from jinja2.exceptions import TemplateError, UndefinedError
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, ConfigDict, Field, field_validator


_ID_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")


class WorkflowStep(BaseModel):
    """One step in a v2 workflow document."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    id: str
    type: str = Field(default="tool")  # tool | analysis | report
    tool: Optional[str] = None
    agent: Optional[str] = None
    objective: str = Field(default="", max_length=500)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    depends_on: List[str] = Field(default_factory=list)
    when: Optional[str] = Field(default=None, max_length=400)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(
                f"Invalid step id '{v}' — must be a Python-style identifier "
                "(letters, digits, underscore; ≤64 chars)"
            )
        return v

    @field_validator("type")
    @classmethod
    def _valid_type(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if cleaned not in {"tool", "analysis", "report"}:
            raise ValueError(
                f"Invalid step type '{v}' — must be one of tool|analysis|report"
            )
        return cleaned


class WorkflowDoc(BaseModel):
    """Top-level v2 workflow document."""

    model_config = ConfigDict(extra="ignore")

    version: int = 1
    name: str = "unnamed"
    description: str = ""
    steps: List[WorkflowStep]
    settings: Dict[str, Any] = Field(default_factory=dict)


@dataclass
class CompiledWorkflow:
    """Compiled, ready-to-execute workflow.

    ``levels`` is a list of "generations" — within each generation, all steps
    are independent of each other and may run in parallel. Generations
    execute strictly in order.
    """

    name: str
    description: str
    settings: Dict[str, Any]
    steps: Dict[str, WorkflowStep]
    levels: List[List[str]] = field(default_factory=list)


# ── Jinja2 sandbox ───────────────────────────────────────────────────────────

# Sandboxed env disables filesystem/network access. StrictUndefined raises on
# missing variables instead of silently rendering empty strings — which would
# turn a typo'd ``{{ discovery.parsedd.hosts }}`` into a no-op.
_JINJA_ENV = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)


class WorkflowCompileError(ValueError):
    """Raised when a workflow document fails validation or has a cycle."""


def compile_workflow(doc: Dict[str, Any]) -> CompiledWorkflow:
    """Validate and compile a workflow YAML dict into ``CompiledWorkflow``.

    Accepts both v1 (flat ``steps`` list, no ``id``) and v2 (typed, with
    ``depends_on``). v1 documents are converted in-place — every step gets a
    synthesized ``id`` from its ``name`` and is chained ``depends_on`` to its
    predecessor (preserving the original sequential semantics).

    Special-case: ``mode: autonomous`` documents have no ``steps`` list.
    They compile to an empty plan; the engine routes them to ``run_autonomous``.
    """
    if not isinstance(doc, dict):
        raise WorkflowCompileError("Workflow document must be a mapping")

    raw = dict(doc)  # don't mutate caller's dict

    # Autonomous mode short-circuit — emit a placeholder so downstream code
    # has a CompiledWorkflow object without trying to schedule any steps.
    if str(raw.get("mode", "")).lower() == "autonomous" or not raw.get("steps"):
        return CompiledWorkflow(
            name=str(raw.get("name", "autonomous")),
            description=str(raw.get("description", "")),
            settings=raw.get("settings", raw.get("agents", {})) or {},
            steps={},
            levels=[],
        )

    # Schema version: accept int (2) or semver string ("2.0.0"). The literal
    # version field is advisory; the operative test is whether any step
    # carries an ``id`` — without it we treat the doc as v1 and migrate so
    # ``web_full_assessment.yaml`` (which is tagged "version: 2.0.0" but uses
    # v1 step schema) compiles cleanly.
    raw_steps = raw.get("steps") or []
    has_v2_ids = any(
        isinstance(s, dict) and isinstance(s.get("id"), str)
        for s in raw_steps
    )

    if not has_v2_ids:
        raw["steps"] = _migrate_v1_steps(raw_steps)
    raw["version"] = 2

    try:
        validated = WorkflowDoc.model_validate(raw)
    except Exception as e:
        raise WorkflowCompileError(f"Workflow validation failed: {e}") from e

    # Build step map and validate uniqueness.
    by_id: Dict[str, WorkflowStep] = {}
    for step in validated.steps:
        if step.id in by_id:
            raise WorkflowCompileError(f"Duplicate step id: {step.id}")
        by_id[step.id] = step

    # Validate depends_on references and detect cycles.
    for step in validated.steps:
        for dep in step.depends_on:
            if dep not in by_id:
                raise WorkflowCompileError(
                    f"Step '{step.id}' depends_on unknown step '{dep}'"
                )
            if dep == step.id:
                raise WorkflowCompileError(f"Step '{step.id}' depends on itself")

    levels = _topological_levels(by_id)

    return CompiledWorkflow(
        name=validated.name,
        description=validated.description,
        settings=validated.settings,
        steps=by_id,
        levels=levels,
    )


def render_parameters(
    params: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Recursively render Jinja2 templates in ``params`` against ``context``.

    Templates may appear in any string value at any depth (dicts/lists are
    walked). Non-string values pass through unchanged. Undefined variables
    raise — silent empty-string fallback would mask broken refs.
    """
    return _render_walk(params, context)


def evaluate_when(expr: Optional[str], context: Dict[str, Any]) -> bool:
    """Evaluate a ``when`` expression. ``None`` means always-run."""
    if expr is None:
        return True
    try:
        rendered = _JINJA_ENV.from_string("{{ " + expr + " }}").render(**context)
    except (TemplateError, UndefinedError) as e:
        raise WorkflowCompileError(f"when expression failed: {e}") from e
    truthy = rendered.strip().lower()
    return truthy not in ("", "false", "none", "0")


# ── Internals ────────────────────────────────────────────────────────────────


def _migrate_v1_steps(steps: List[Any]) -> List[Dict[str, Any]]:
    """Convert v1 steps (no id, no depends_on) to v2.

    Each v1 step's ``name`` becomes its ``id`` (sanitized). Steps are chained
    ``depends_on`` their immediate predecessor so the engine preserves the
    original sequential order.
    """
    out: List[Dict[str, Any]] = []
    prev_id: Optional[str] = None
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise WorkflowCompileError(f"Step #{i} is not a mapping")
        sid = step.get("id") or _sanitize_id(step.get("name") or f"step_{i}")
        new = dict(step)
        new["id"] = sid
        if "depends_on" not in new and prev_id is not None:
            new["depends_on"] = [prev_id]
        prev_id = sid
        out.append(new)
    return out


def _sanitize_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", raw)
    if not cleaned or not cleaned[0].isalpha() and cleaned[0] != "_":
        cleaned = "step_" + cleaned
    return cleaned[:64]


def _topological_levels(by_id: Dict[str, WorkflowStep]) -> List[List[str]]:
    """Kahn's algorithm — group nodes by readiness generation.

    Within a generation, all nodes have all dependencies satisfied and are
    independent of each other; they can be scheduled in parallel.
    """
    in_deg: Dict[str, int] = {sid: len(s.depends_on) for sid, s in by_id.items()}
    dependents: Dict[str, List[str]] = {sid: [] for sid in by_id}
    for sid, step in by_id.items():
        for dep in step.depends_on:
            dependents[dep].append(sid)

    levels: List[List[str]] = []
    ready = sorted(sid for sid, d in in_deg.items() if d == 0)
    seen: Set[str] = set()

    while ready:
        levels.append(ready)
        seen.update(ready)
        next_ready: List[str] = []
        for sid in ready:
            for child in dependents[sid]:
                in_deg[child] -= 1
                if in_deg[child] == 0:
                    next_ready.append(child)
        ready = sorted(next_ready)

    if len(seen) != len(by_id):
        unresolved = sorted(set(by_id) - seen)
        raise WorkflowCompileError(
            f"Cycle detected — could not order steps: {unresolved}"
        )
    return levels


def _render_walk(node: Any, context: Dict[str, Any]) -> Any:
    if isinstance(node, str):
        if "{{" not in node and "{%" not in node:
            return node
        try:
            return _JINJA_ENV.from_string(node).render(**context)
        except (TemplateError, UndefinedError) as e:
            raise WorkflowCompileError(f"Template render failed for {node!r}: {e}") from e
    if isinstance(node, dict):
        return {k: _render_walk(v, context) for k, v in node.items()}
    if isinstance(node, list):
        return [_render_walk(v, context) for v in node]
    return node

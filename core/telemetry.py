"""
Tool selection telemetry — A5 Phase 1.

Anonymises and exports session-level tool-selection records for offline
training of a learned ranker. Per row:

    target_type, phase, prior_findings_summary, tool_chosen,
    findings_yielded, duration_seconds, success

Anonymisation rules:
  * targets are bucketed (``ip|domain|url``) — never raw values.
  * tool names kept (needed for class label).
  * findings counts kept (numeric only).
  * raw outputs / commands / secrets STRIPPED entirely.

Output is JSONL — one row per tool execution, append-friendly. Operators
opt in by setting ``telemetry.enabled: true`` in guardian.yaml or by
running ``guardian telemetry export <session_file>``. Disabled by default.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from utils.helpers import is_valid_domain, is_valid_ip, is_valid_url


@dataclass
class TelemetryRow:
    """Single anonymised telemetry record."""

    session_id: str
    target_type: str           # ip | domain | url | unknown
    phase: str                 # reconnaissance | scanning | analysis | reporting
    tool: str
    duration: float
    findings_yielded: int
    success: bool
    prior_tool_count: int      # how many tools ran before this one
    prior_findings_count: int  # findings already in memory at selection time


def _bucket_target(target: str) -> str:
    """Classify target without leaking the raw value."""
    if not target:
        return "unknown"
    if is_valid_url(target):
        return "url"
    if is_valid_ip(target):
        return "ip"
    if is_valid_domain(target):
        return "domain"
    return "unknown"


def session_to_rows(state: Dict[str, Any]) -> List[TelemetryRow]:
    """Convert a saved session JSON dict into telemetry rows.

    ``state`` is whatever ``PentestMemory.save_state`` produced:
    ``{session_id, target, phase, findings, tool_executions, ...}``.

    Order matters — we walk ``tool_executions`` and use prior counts as
    features. Skipped/failed runs still emit a row (success=False) so the
    learner can model "tool X tends to skip on target type Y".
    """
    rows: List[TelemetryRow] = []
    session_id = str(state.get("session_id") or "unknown")
    target = str(state.get("target") or "")
    target_type = _bucket_target(target)
    phase = str(state.get("current_phase") or state.get("phase") or "unknown")
    findings = state.get("findings") or []

    prior_tool_count = 0
    prior_findings_count = 0
    # Group findings by tool to count yield per execution.
    findings_by_tool: Dict[str, int] = {}
    for f in findings:
        t = (f or {}).get("tool", "")
        if t:
            findings_by_tool[t] = findings_by_tool.get(t, 0) + 1

    for exec_record in state.get("tool_executions") or []:
        tool = str((exec_record or {}).get("tool") or "")
        if not tool:
            continue
        duration = float(exec_record.get("duration") or 0.0)
        success = int(exec_record.get("exit_code", 1)) == 0
        yielded = exec_record.get("findings_count")
        if not isinstance(yielded, int) or yielded < 0:
            # Fall back to per-tool count — first-occurrence assignment.
            yielded = findings_by_tool.pop(tool, 0)

        rows.append(TelemetryRow(
            session_id=session_id,
            target_type=target_type,
            phase=phase,
            tool=tool,
            duration=round(duration, 3),
            findings_yielded=int(yielded),
            success=success,
            prior_tool_count=prior_tool_count,
            prior_findings_count=prior_findings_count,
        ))
        prior_tool_count += 1
        prior_findings_count += int(yielded)

    return rows


def write_jsonl(rows: Iterable[TelemetryRow], out_path: Path) -> int:
    """Append rows to a JSONL file. Returns the number written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out_path, "a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(asdict(row), separators=(",", ":")))
            fh.write("\n")
            n += 1
    return n


def export_session_file(session_file: Path, out_path: Path) -> int:
    """Read one ``session_<id>.json`` and append its rows to ``out_path``."""
    with open(session_file, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    rows = session_to_rows(state)
    return write_jsonl(rows, out_path)


def export_directory(reports_dir: Path, out_path: Path) -> int:
    """Bulk-export every ``session_*.json`` under a reports directory."""
    total = 0
    for f in reports_dir.glob("session_*.json"):
        try:
            total += export_session_file(f, out_path)
        except Exception:
            # Skip malformed sessions silently — a partial corpus is fine.
            continue
    return total

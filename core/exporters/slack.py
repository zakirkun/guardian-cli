"""
Slack / Discord webhook exporter.

Posts a compact summary of session findings to an incoming-webhook URL.
Works with both Slack-flavoured and Discord-flavoured webhooks because
the message format is intentionally minimal.

The ``send`` function is async — uses aiohttp if installed, otherwise
falls back to urllib so the dep stays soft.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional

from core.memory import Finding, PentestMemory


_SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high":     ":warning:",
    "medium":   ":large_orange_diamond:",
    "low":      ":large_blue_circle:",
    "info":     ":information_source:",
}


def build_payload(
    memory: PentestMemory,
    *,
    top_n: int = 5,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a Slack/Discord-compatible JSON payload.

    Single ``text`` field — both platforms accept it. Discord ignores
    Slack mrkdwn but the plain text fallback renders cleanly.
    """
    summary = memory.get_findings_summary()
    severity_line = " ".join(
        f"{_SEVERITY_EMOJI[s]} {summary[s]} {s}"
        for s in ("critical", "high", "medium", "low", "info")
        if summary.get(s)
    ) or "No findings"

    top = sorted(
        (f for f in memory.findings if not f.false_positive),
        key=lambda f: _severity_rank(f.severity),
    )[:top_n]
    top_lines = [
        f"  • [{(f.severity or 'info').upper()}] {f.title or 'Untitled'}"
        for f in top
    ]

    text_lines = [
        title or f"*Guardian session {memory.session_id}*",
        f"Target: `{memory.target}`",
        f"Findings: {severity_line}",
    ]
    if top_lines:
        text_lines.append("Top findings:")
        text_lines.extend(top_lines)

    return {"text": "\n".join(text_lines)}


def _severity_rank(severity: Optional[str]) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((severity or "info").lower(), 5)


def post(webhook_url: str, payload: Dict[str, Any], timeout: int = 10) -> int:
    """Synchronously POST a JSON payload to a webhook. Returns HTTP status."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-supplied URL
        return resp.status

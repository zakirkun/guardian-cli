"""
Multi-agent debate triage.

Replaces single-pass analyst confidence with a three-role debate:
  * RED_ADVOCATE   argues finding is real
  * BLUE_ADVOCATE  argues finding is FP
  * JUDGE          issues verdict + severity adjustment

Triggered only on findings the analyst flagged with
``false_positive_probability == "MEDIUM"`` to keep cost bounded.
Confident verdicts (LOW = clearly real, HIGH = clearly FP) skip debate.

Public entry point: ``DebateTriage.triage(finding) -> DebateVerdict``.

Acceptance metric (per A6 evals): F1 ≥ single-agent baseline + 5pp on
the labeled FP/TP corpus.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.agent import BaseAgent
from core.memory import Finding, PentestMemory
from utils.sanitize import wrap_untrusted

from ai.prompt_templates.debate import (
    BLUE_ADVOCATE_PROMPT,
    BLUE_ADVOCATE_SYSTEM_PROMPT,
    JUDGE_PROMPT,
    JUDGE_SYSTEM_PROMPT,
    RED_ADVOCATE_PROMPT,
    RED_ADVOCATE_SYSTEM_PROMPT,
)


_VALID_VERDICTS = {"REAL", "FALSE_POSITIVE", "VERIFY_MANUALLY"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class DebateVerdict:
    """Outcome of a single debate round."""

    finding_id: str
    verdict: str           # REAL | FALSE_POSITIVE | VERIFY_MANUALLY
    adjusted_severity: str
    rationale: str
    confidence: int
    red_argument: str
    blue_argument: str
    triggered: bool        # False if debate was skipped (already-confident)


class _RedAdvocate(BaseAgent):
    name_prefix = "RedAdvocate"

    async def execute(self, **kwargs):  # pragma: no cover — used via debate
        return {}


class _BlueAdvocate(BaseAgent):
    name_prefix = "BlueAdvocate"

    async def execute(self, **kwargs):  # pragma: no cover
        return {}


class _Judge(BaseAgent):
    name_prefix = "Judge"

    async def execute(self, **kwargs):  # pragma: no cover
        return {}


class DebateTriage:
    """Orchestrate a three-role debate over an ambiguous finding."""

    def __init__(self, config: Dict[str, Any], gemini_client, memory: PentestMemory):
        self.config = config
        self.memory = memory
        # Three independent agents — each gets its own thinking-step counter.
        # Same underlying client; distinct system prompts via .think().
        self.red = _RedAdvocate("RedAdvocate", config, gemini_client, memory)
        self.blue = _BlueAdvocate("BlueAdvocate", config, gemini_client, memory)
        self.judge = _Judge("Judge", config, gemini_client, memory)

    async def triage(self, finding: Finding) -> DebateVerdict:
        """Run debate against a single finding.

        If the finding's pre-debate signal is decisive — already labeled
        verified-real or high-FP-probability — short-circuit with
        ``triggered=False`` so the caller can record the cheap path.
        """
        fp_prob = self._extract_fp_probability(finding)
        if fp_prob != "MEDIUM":
            return DebateVerdict(
                finding_id=finding.id,
                verdict="REAL" if fp_prob == "LOW" else "FALSE_POSITIVE",
                adjusted_severity=finding.severity,
                rationale=f"Pre-debate confidence {fp_prob} — debate skipped",
                confidence=80,
                red_argument="",
                blue_argument="",
                triggered=False,
            )

        evidence = wrap_untrusted(finding.evidence or finding.description)
        technologies = wrap_untrusted(
            ", ".join(self.memory.context.get("technologies", [])) or "Unknown"
        )

        red_resp = await self.red.think(
            RED_ADVOCATE_PROMPT.format(
                tool=finding.tool,
                title=finding.title,
                severity=finding.severity,
                target=finding.target,
                evidence=evidence,
                technologies=technologies,
                prior_findings_count=len(self.memory.findings),
            ),
            RED_ADVOCATE_SYSTEM_PROMPT,
        )
        blue_resp = await self.blue.think(
            BLUE_ADVOCATE_PROMPT.format(
                tool=finding.tool,
                title=finding.title,
                severity=finding.severity,
                target=finding.target,
                evidence=evidence,
                technologies=technologies,
            ),
            BLUE_ADVOCATE_SYSTEM_PROMPT,
        )

        red_arg = self._extract_argument(red_resp.get("response", ""))
        blue_arg = self._extract_argument(blue_resp.get("response", ""))

        judge_resp = await self.judge.think(
            JUDGE_PROMPT.format(
                tool=finding.tool,
                title=finding.title,
                severity=finding.severity,
                # Judge sees the advocates' arguments wrapped — they came
                # from earlier LLM calls, but their structure isn't trusted.
                red_argument=wrap_untrusted(red_arg),
                blue_argument=wrap_untrusted(blue_arg),
            ),
            JUDGE_SYSTEM_PROMPT,
        )
        verdict_obj = self._parse_verdict(judge_resp.get("response", ""))

        return DebateVerdict(
            finding_id=finding.id,
            verdict=verdict_obj["verdict"],
            adjusted_severity=verdict_obj["adjusted_severity"],
            rationale=verdict_obj["rationale"],
            confidence=verdict_obj["confidence"],
            red_argument=red_arg[:1000],
            blue_argument=blue_arg[:1000],
            triggered=True,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_fp_probability(finding: Finding) -> str:
        """Read fp probability from the finding description if present.

        Findings emitted by the analyst include a
        ``False_Positive: <LOW|MEDIUM|HIGH>`` line in their description.
        Defaults to ``MEDIUM`` (debate-trigger) when not parseable.
        """
        if not finding.description:
            return "MEDIUM"
        m = re.search(r"False[_\s]Positive[:\s]+(LOW|MEDIUM|HIGH)", finding.description, re.I)
        if m:
            return m.group(1).upper()
        return "MEDIUM"

    @staticmethod
    def _extract_argument(response: str) -> str:
        """Pull ``argument`` field out of an advocate's JSON reply.

        Falls back to the raw response when JSON parsing fails — debate
        still proceeds, just with a less structured input to the judge.
        """
        m = re.search(r"\{[\s\S]*\}", response)
        if not m:
            return response[:1000]
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return response[:1000]
        arg = obj.get("argument") or obj.get("reasoning") or response
        return str(arg)[:1500]

    @staticmethod
    def _parse_verdict(response: str) -> Dict[str, Any]:
        """Parse + validate a judge JSON verdict.

        Defaults to ``VERIFY_MANUALLY`` when the verdict is unparseable —
        better to escalate than to ship a guessed conclusion.
        """
        out: Dict[str, Any] = {
            "verdict": "VERIFY_MANUALLY",
            "adjusted_severity": "medium",
            "rationale": response[:500],
            "confidence": 50,
        }
        m = re.search(r"\{[\s\S]*\}", response)
        if not m:
            return out
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return out

        v = str(obj.get("verdict", "")).upper().strip()
        if v in _VALID_VERDICTS:
            out["verdict"] = v

        sev = str(obj.get("adjusted_severity", "")).lower().strip()
        if sev in _VALID_SEVERITIES:
            out["adjusted_severity"] = sev

        rationale = obj.get("rationale", "")
        if isinstance(rationale, str):
            out["rationale"] = rationale[:1000]

        try:
            conf = int(obj.get("confidence", 50))
            out["confidence"] = max(0, min(100, conf))
        except (TypeError, ValueError):
            pass

        return out

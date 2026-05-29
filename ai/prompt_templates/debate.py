"""
Prompt templates for the Triage Debate agents.

Three agents engage in a structured debate:
  * RED_ADVOCATE  — argues the finding is REAL (true positive)
  * BLUE_ADVOCATE — argues the finding is FALSE positive
  * JUDGE         — cold-reads the transcript, issues verdict

This is invoked only on findings the analyst flagged
``false_positive_probability=MEDIUM``. Confident verdicts (LOW = real,
HIGH = FP) skip the debate to keep token cost bounded.
"""

from utils.sanitize import UNTRUSTED_CONTENT_RULE


# ── Shared system prompt fragment ────────────────────────────────────────────
_DEBATE_BASE = """You are participating in a structured triage debate. The goal \
is to determine whether a security finding is genuine or a false positive. The \
debate has three roles: RED_ADVOCATE, BLUE_ADVOCATE, and JUDGE.

""" + UNTRUSTED_CONTENT_RULE + """

## Debate rules
- Cite specific evidence from the tool output (quote with backticks).
- Do not invent facts. If you don't know, say so.
- Keep your argument under 250 words.
- Do not address the opposing advocate directly; address the judge.
"""


# ── RED ADVOCATE — argues finding is REAL ────────────────────────────────────
RED_ADVOCATE_SYSTEM_PROMPT = _DEBATE_BASE + """
## Your role: RED_ADVOCATE
You argue that the finding IS a real, exploitable vulnerability. Build the
strongest case using the evidence. Identify the precise attack path, the \
business impact, and why a skeptical reviewer should still accept it.

You must be honest — if the evidence genuinely doesn't support a real \
vulnerability, say so explicitly rather than fabricating support.
"""

RED_ADVOCATE_PROMPT = """## FINDING UNDER REVIEW
Tool:     {tool}
Title:    {title}
Severity: {severity}
Target:   {target}

## EVIDENCE (untrusted tool output)
{evidence}

## CONTEXT
Detected technologies: {technologies}
Prior findings (this session): {prior_findings_count}

## YOUR TASK
Argue why this finding IS a real vulnerability. Output JSON:
  {{
    "argument": "<your reasoning, 50-250 words>",
    "key_evidence": ["<quoted snippet 1>", "<quoted snippet 2>"],
    "exploit_path": "<one-sentence description of how an attacker exploits this>",
    "confidence": <0-100>
  }}
"""


# ── BLUE ADVOCATE — argues finding is FALSE POSITIVE ─────────────────────────
BLUE_ADVOCATE_SYSTEM_PROMPT = _DEBATE_BASE + """
## Your role: BLUE_ADVOCATE
You argue that the finding is a FALSE POSITIVE. Identify the most likely \
reasons the tool over-reported: generic template, mismatched tech stack, \
benign banner, version misreading, or attack path that requires impossible \
preconditions.

You must be honest — if the finding really IS exploitable, say so explicitly \
rather than fabricating a refutation.
"""

BLUE_ADVOCATE_PROMPT = """## FINDING UNDER REVIEW
Tool:     {tool}
Title:    {title}
Severity: {severity}
Target:   {target}

## EVIDENCE (untrusted tool output)
{evidence}

## CONTEXT
Detected technologies: {technologies}

## YOUR TASK
Argue why this finding is a FALSE POSITIVE. Output JSON:
  {{
    "argument": "<your reasoning, 50-250 words>",
    "fp_indicators": ["<reason 1>", "<reason 2>"],
    "missing_preconditions": ["<what would need to be true for it to be real>"],
    "confidence": <0-100>
  }}
"""


# ── JUDGE — issues verdict ───────────────────────────────────────────────────
JUDGE_SYSTEM_PROMPT = _DEBATE_BASE + """
## Your role: JUDGE
You see both advocates' arguments. Issue a verdict using the same evidence \
the advocates saw — do NOT introduce new evidence.

Severity adjustments must be conservative — only downgrade severity when \
the BLUE_ADVOCATE has demonstrated specific FP indicators, not just \
plausibility.
"""

JUDGE_PROMPT = """## ORIGINAL FINDING
Tool:     {tool}
Title:    {title}
Severity: {severity}

## RED_ADVOCATE ARGUMENT (finding is real)
{red_argument}

## BLUE_ADVOCATE ARGUMENT (finding is false positive)
{blue_argument}

## YOUR TASK
Issue a verdict. Output JSON only:
  {{
    "verdict": "REAL" | "FALSE_POSITIVE" | "VERIFY_MANUALLY",
    "adjusted_severity": "critical|high|medium|low|info",
    "rationale": "<one paragraph, ≤300 words, citing the strongest argument>",
    "confidence": <0-100>
  }}
"""

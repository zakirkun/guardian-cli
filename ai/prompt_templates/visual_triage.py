"""
Prompt templates for the Visual Triage analyst sub-step (A3).

A vision-capable LLM (gpt-4o, Claude 3.5+, Gemini 1.5+) reads a captured
screenshot alongside the textual finding context and returns enriched
descriptions grounded in image evidence — XSS popup actually visible,
admin panel present, default credentials prompt, debug info exposed.

Output schema mirrors the analyst's main interpret schema so downstream
parsing is unchanged.
"""

from utils.sanitize import UNTRUSTED_CONTENT_RULE


VISUAL_TRIAGE_SYSTEM_PROMPT = (
    """You are a security-focused visual analyst. You receive a screenshot \
plus textual context from prior recon, and your job is to ground the \
finding description in what the image actually shows.

"""
    + UNTRUSTED_CONTENT_RULE
    + """

## Rules
- Describe ONLY what is visibly present in the screenshot.
- If the textual finding contradicts the screenshot, say so.
- Identify visual indicators: error pages, default panels, exposed \
secrets, debug consoles, framework login pages, mismatched branding.
- Never claim exploitability you cannot confirm visually.
- Keep your description under 150 words.
"""
)


VISUAL_TRIAGE_PROMPT = """## TARGET CONTEXT
URL:        {url}
Tool:       {tool}
Title:      {title}
Severity:   {severity}

## TEXT EVIDENCE (untrusted)
{evidence}

## YOUR TASK
Examine the screenshot carefully. Output JSON only:
  {{
    "visible_indicators": ["<short bullet>", ...],
    "page_type": "<login | error | admin_panel | debug_console | default_install | static_marketing | unknown>",
    "supports_finding": true | false,
    "enriched_description": "<≤150 words describing what is visible and how it relates to the finding>",
    "confidence": <0-100>
  }}
"""

"""
Prompt templates for the Reporter Agent
Generates professional, standards-aligned penetration testing reports
"""

# =============================================================================
# SYSTEM PROMPT  –  injected once per session
# =============================================================================
REPORTER_SYSTEM_PROMPT = """You are the Report Generator for Guardian, an enterprise-grade \
AI-powered penetration testing platform.

## Your Role
You produce professional penetration testing reports that are accurate, well-structured, \
and usable by both technical and non-technical stakeholders. Your reports are a legal and \
contractual deliverable – accuracy and clarity are paramount.

## Core Responsibilities
1. **Audience Stratification** – Every report has two audiences:
   - **Executive Audience**: Board, CISO, non-technical managers – they need business risk \
     language, financial impact estimates, and priority actions in plain English.
   - **Technical Audience**: Security engineers, DevSecOps – they need exact CVEs, CVSS \
     vectors, affected endpoints, config keys, code snippets, and step-by-step remediation.
2. **Standards Alignment** – Reference applicable standards where relevant:
   - ISO 27001:2022 Annex A controls for remediation mapping
   - PCI-DSS v4.0 requirements if payment-card scope
   - OWASP Top 10 (web) / OWASP API Security Top 10 (API targets)
   - NIST SP 800-53 control families for infrastructure findings
3. **Evidence Integrity** – Every finding section must include:
   - The exact tool output or screenshot reference that proves the finding
   - The execution ID that links to the raw session capture
4. **Remediation Quality** – Recommendations must be:
   - Specific (file path, config key, package name + version)
   - Achievable (realistic effort estimation)
   - Prioritised (Quick Win vs. Short-term vs. Long-term)
5. **Transparency** – Include a full AI Decision Trace so the client can audit every
   automated decision made during the engagement.

## Report Structure (mandatory)
1. Cover Page & Metadata
2. Executive Summary (<=1 page, plain English)
3. Scope & Methodology
4. Risk Overview Dashboard (severity counts + overall posture rating)
5. Detailed Findings (one subsection per finding, ordered by severity)
6. Remediation Roadmap (Quick Wins → Short-term → Long-term)
7. AI Decision Trace & Reasoning Log
8. AI Usage & Cost Summary
9. Appendix: Raw Evidence & Tool Commands

## Formatting Rules
- Use clear Markdown headings (H1 → H3 max depth)
- Use tables for comparison data
- Use code blocks for commands and configuration
- Bold the severity level at the start of each finding title
- Never truncate evidence – include full tool output references"""


# =============================================================================
# EXECUTIVE SUMMARY PROMPT
# =============================================================================
REPORTER_EXECUTIVE_SUMMARY_PROMPT = """Write the Executive Summary section for this \
penetration test report.

═══════════════════════════════════════════════
 ENGAGEMENT METADATA
═══════════════════════════════════════════════
Target:            {target}
Scope:             {scope}
Assessment Date:   {assessment_date}
Duration:          {duration}
Session ID:        {session_id}

Finding Counts:
  CRITICAL: {critical_count}
  HIGH:     {high_count}
  MEDIUM:   {medium_count}
  LOW:      {low_count}
  INFO:     {info_count}
  Total:    {findings_count}

Overall Risk Rating: {risk_rating}

Top 3 Critical Issues:
{top_issues}

═══════════════════════════════════════════════
 INSTRUCTIONS
═══════════════════════════════════════════════
Write 3–4 paragraphs suitable for a board-level reader:

**Paragraph 1 – Engagement Overview**
What was tested, when, and using what approach (automated AI-driven assessment).

**Paragraph 2 – Key Risk Findings**
Describe the most critical risks in business terms (data breach risk, service disruption, \
regulatory exposure). Do NOT use technical jargon. Quantify impact where possible \
(e.g. "could expose customer PII of up to X users").

**Paragraph 3 – Security Posture Assessment**
Overall security maturity rating with a brief justification. Compare to industry baseline if able.

**Paragraph 4 – Recommended Priority Actions**
3 bullet points, each one sentence, ordered by urgency. Use action verbs \
(Patch, Disable, Rotate, Implement, Enable).

Keep language confident and clear. Avoid passive voice. This section will be read first."""


# =============================================================================
# TECHNICAL FINDINGS PROMPT
# =============================================================================
REPORTER_TECHNICAL_FINDINGS_PROMPT = """Write the Detailed Technical Findings section.

FINDINGS DATA:
{findings}

For EACH finding, produce a subsection in this exact structure:

---
### [SEVERITY] Finding Title

**Severity:** CRITICAL / HIGH / MEDIUM / LOW / INFO
**CVSS 3.1 Score:** X.X (`CVSS:3.1/AV:.../...`)
**CWE:** CWE-XXXX – Name
**CVE:** CVE-XXXX-XXXXX (if applicable)
**OWASP:** Axx – Category (if applicable)
**Affected Component:** <host / endpoint / service>
**Execution ID:** <links to raw evidence>

#### Description
<2–3 sentences: what the vulnerability is, why it exists, technical root cause>

#### Evidence
```
<exact tool output proving the finding>
```

#### Impact Analysis
<What can an attacker do? Data exposure? RCE? Privilege escalation? Service disruption?>
Map to MITRE ATT&CK technique (T####) if applicable.

#### Remediation
**Immediate Action (<=24h):** <specific emergency step>
**Short-term Fix (<=30 days):** <proper remediation with commands or config>
**Verification:** <how to confirm the fix is effective>

**Standards Reference:** <ISO 27001 control / PCI-DSS / NIST control>
---"""


# =============================================================================
# REMEDIATION ROADMAP PROMPT
# =============================================================================
REPORTER_REMEDIATION_PROMPT = """Create a prioritised Remediation Roadmap.

FINDINGS:
{findings}

AFFECTED SYSTEMS:
{affected_systems}

Produce a three-tier action plan:

## 🔴 Quick Wins (Complete within 24–72 hours)
*High impact, low effort. Do these immediately.*

| # | Action | Finding | Effort | Impact |
|---|--------|---------|--------|--------|
(fill rows)

## 🟠 Short-term (Complete within 30 days)
*Important fixes requiring planning but no architectural change.*

| # | Action | Finding | Effort | Impact |
|---|--------|---------|--------|--------|
(fill rows)

## 🟡 Long-term (Complete within 90 days)
*Architectural improvements and process changes.*

| # | Action | Finding | Effort | Impact |
|---|--------|---------|--------|--------|
(fill rows)

## Implementation Notes
- For each Quick Win: include exact commands or config snippets
- Flag any actions that require vendor patches or third-party involvement
- Estimate engineer-hours per action where possible

## Verification Checklist
Provide a post-remediation testing checklist for the top 5 actions."""


# =============================================================================
# AI DECISION TRACE PROMPT
# =============================================================================
REPORTER_AI_TRACE_PROMPT = """Document the complete AI decision-making process for this \
penetration test engagement.

═══════════════════════════════════════════════
 AI DECISIONS LOG
═══════════════════════════════════════════════
{ai_decisions}

═══════════════════════════════════════════════
 THINKING CHAIN SUMMARY
═══════════════════════════════════════════════
{thinking_chain}

═══════════════════════════════════════════════
 WORKFLOW EXECUTED
═══════════════════════════════════════════════
{workflow}

Write the AI Decision Trace section covering:

1. **Strategic Decisions** (Planner Agent)
   - List each major decision with reasoning summary
   - Note any pivots or adaptive changes to the plan

2. **Tool Selection Rationale** (Tool Agent)
   - Why each tool was chosen for its task
   - Parameters selected and justification

3. **Analysis Methodology** (Analyst Agent)
   - How findings were extracted and classified
   - False positive filtering applied
   - Correlation logic used

4. **Confidence Assessment**
   - Overall confidence in findings: HIGH / MEDIUM / LOW
   - Areas where manual review is strongly recommended

5. **Limitations & Caveats**
   - What the AI could not assess automatically
   - External factors that may affect result accuracy

This section exists for audit transparency. Write in third person, past tense."""


# =============================================================================
# TOKEN COST SECTION PROMPT
# =============================================================================
REPORTER_TOKEN_COST_SECTION_PROMPT = """Generate the "AI Usage & Cost Summary" appendix \
section for this report.

TOKEN LEDGER:
{token_ledger}

TOTAL SUMMARY:
{token_summary}

Write a clean, professional appendix section with:

## AI Usage & Cost Summary

### Overview
Brief paragraph explaining that Guardian used AI extensively throughout the assessment and \
why tracking this matters (reproducibility, cost accountability, auditing).

### Token Usage by Agent

| Agent | Model | Provider | Prompt Tokens | Completion Tokens | Total Tokens | Est. Cost (USD) |
|-------|-------|----------|---------------|-------------------|--------------|-----------------|
{token_table_placeholder}

### Token Usage by Provider

| Provider | Total Tokens | Est. Cost (USD) |
|----------|--------------|-----------------|
{provider_table_placeholder}

### Session Totals

| Metric | Value |
|--------|-------|
| Total Prompt Tokens | {total_prompt} |
| Total Completion Tokens | {total_completion} |
| Total Tokens | {total_tokens} |
| Estimated Total Cost (USD) | ${total_cost} |
| Thinking Steps Recorded | {thinking_steps} |
| AI Decisions Made | {decision_count} |

### Notes
- Costs are estimates based on publicly listed pricing in `config/guardian.yaml` at the time \
  of the assessment. Actual billed amounts may differ.
- Token counts include all agents: Planner, Tool Selector, Analyst, and Reporter.
- Pricing configuration can be updated in `config/guardian.yaml` under `ai.pricing`.
"""

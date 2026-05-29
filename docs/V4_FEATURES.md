# Guardian v4.0 Features

Reference for the v4.0 R&D track. Covers RAG, multi-agent debate, vision
triage, plugin contract, learned tool selection, judge model, and the
new tool wrappers in Track B.

## Track A — AI / Agent R&D

### A1. RAG Knowledge Base

Local SQLite + FTS5 corpus over CVE / CWE / MITRE ATT&CK / nuclei
metadata. Eliminates hallucinated CVE references in analyst reports.

#### Architecture

```
core/knowledge_base.py
├── KBEntry             dataclass — id, kind, title, summary, severity, cvss, cwe, refs
├── KBHit               dataclass — entry + score
├── KnowledgeBase       SQLite + FTS5 store, optional embedding rerank
└── hits_to_prompt_block  delimited reference block for analyst prompt

cli/commands/kb.py
├── seed                bundled offline corpus
├── update --kind       ingest pre-downloaded NVD / MITRE / nuclei feed
├── query               ad-hoc retrieval
└── status              row counts per kind
```

#### Schema

```
entries(id PK, kind, title, summary, severity, cvss, cwe, refs JSON, updated)
fts(id, title, summary, refs)              -- FTS5 virtual, content=entries
embeddings(id PK, vec BLOB)                -- optional, populated only if
                                              sentence-transformers extra is installed
```

#### Use

```bash
# 1. Seed bundled corpus
python -m cli.main kb seed

# 2. Ingest pre-downloaded feed
python -m cli.main kb update --kind cve --file ./nvd-2025.json

# 3. Confirm grounding
python -m cli.main kb query "log4j JNDI" --top 5

# 4. Enable analyst grounding
cat >> config/guardian.yaml <<EOF
rag:
  enabled: true
  top_k: 5
EOF
```

When `rag.enabled` is true, the Analyst's `interpret_output` prompt
includes a `[BEGIN_KB_REFERENCES] ... [END_KB_REFERENCES]` block of
top-k matches. The block is wrapped in `<UNTRUSTED_TOOL_OUTPUT>`
delimiters even though it's local — defends against poisoned upstream
feed entries injecting instructions.

#### Acceptance metric

CVE-match rate on a held-out set of 50 nuclei findings: target >85%.
Baseline (no RAG): estimated <50%.

---

### A2. Multi-Agent Debate Triage

Three-role debate over ambiguous findings. Replaces single-pass analyst
self-critique with adversarial agents converging via a judge.

#### Architecture

```
core/agents/debate_triage.py
├── DebateTriage         orchestrator
│   ├── triage(finding)  short-circuits when fp_probability != MEDIUM
│   ├── _RedAdvocate     argues finding is REAL
│   ├── _BlueAdvocate    argues finding is FALSE_POSITIVE
│   └── _Judge           cold-reads transcript, issues verdict
└── DebateVerdict        dataclass result

ai/prompt_templates/debate.py
├── RED_ADVOCATE_SYSTEM_PROMPT  / RED_ADVOCATE_PROMPT
├── BLUE_ADVOCATE_SYSTEM_PROMPT / BLUE_ADVOCATE_PROMPT
└── JUDGE_SYSTEM_PROMPT         / JUDGE_PROMPT
```

#### Cost gating

The debate runs only on findings the analyst flagged
`false_positive_probability=MEDIUM`. Confident verdicts (`LOW` ⇒ real,
`HIGH` ⇒ FP) skip the debate. Token cost stays bounded.

#### Workflow integration

```yaml
- id: triage_debate
  type: analysis
  agent: debate
  depends_on: [correlate]
```

See `workflows/web_pentest_with_debate.yaml`.

#### Verdict output

```
{
  "verdict": "REAL" | "FALSE_POSITIVE" | "VERIFY_MANUALLY",
  "adjusted_severity": "critical|high|medium|low|info",
  "rationale": "...",
  "confidence": 0-100
}
```

The judge's adjustments mutate the finding in memory (severity,
`false_positive` flag) and append a verdict block to `description`.

#### Acceptance metric

F1 ≥ single-agent baseline + 5pp on the labeled FP/TP corpus (`evals/
datasets/`).

---

### A3. Vision-LLM Visual Triage

Headless screenshot capture + image-grounded analyst sub-step.

#### Architecture

```
tools/playwright_screenshot.py
└── PlaywrightScreenshotTool   chromium headless, captures full-page PNGs

core/agents/visual_triage.py
└── VisualTriage
    ├── triage_findings()      walk memory, match shots to findings, enrich
    ├── _best_finding_for_url  exact host > tool-class fallback
    └── _enrich_one            calls provider.generate_with_images

ai/prompt_templates/visual_triage.py
└── VISUAL_TRIAGE_SYSTEM_PROMPT / _PROMPT
```

#### Provider support

Vision is optional capability on `BaseProvider`:

```python
def supports_vision(self) -> bool: ...
async def generate_with_images(prompt, images, system_prompt) -> dict: ...
```

| Provider | Vision support |
|---|---|
| OpenAI (gpt-4o, gpt-4-turbo, gpt-4-vision) | ✅ |
| Claude (claude-3+) | ✅ |
| Gemini | not yet implemented |
| Ollama | not yet implemented |
| OpenAI-compatible | not yet implemented |

When the active provider lacks vision support, visual triage skips
silently with a logged reason.

#### Workflow integration

```yaml
- id: shots
  type: tool
  tool: playwright_screenshot
  depends_on: [discovery]

- id: visual_triage
  type: analysis
  agent: visual
  depends_on: [shots, vuln_scan]
```

See `workflows/web_visual_pentest.yaml`.

#### Install

```bash
pip install playwright
python -m playwright install chromium
```

#### Output

For each enriched finding, `description` is appended with:

```
[Visual Triage — page_type=admin_panel, supports=yes, conf=80]
admin login form visible with default Django banner...
Indicators: login form; django logo
```

`raw_evidence` gains a `screenshot: <path>` line.

---

### A4. Plugin Contract

Provider AND tool registries are now entry-point discoverable. Third
parties can ship a separate package without forking Guardian.

#### Provider registration

```toml
[project.entry-points."guardian.providers"]
my_provider = "my_pkg.my_provider:MyProvider"
```

#### Tool registration

```toml
[project.entry-points."guardian.tools"]
my_scanner = "my_pkg.my_scanner:MyScannerTool"
```

In-tree wins on collisions — plugins cannot silently override a core
provider/tool. Plugin tools default to risk class `active`; override by
extending `TOOL_RISK_CLASS` from your plugin's `__init__.py`.

#### New providers shipped

- **Ollama** (`ai/providers/ollama_provider.py`) — local LLM via HTTP.
  Set `OLLAMA_HOST` env var; uses `prompt_eval_count` / `eval_count`
  for token tracking.
- **OpenAI-compatible** (`ai/providers/openai_compatible_provider.py`) —
  vLLM / LM Studio / Together / Groq via custom `base_url`.

Full plugin authoring guide: [`PLUGIN_GUIDE.md`](PLUGIN_GUIDE.md).

---

### A5. Learned Tool Selection (offline)

Anonymised session telemetry trains a count-table classifier that
predicts the best next tool given (target_type, phase, prior counts).

#### Architecture

```
core/telemetry.py                  anonymise sessions → JSONL
core/learners/tool_ranker.py       train + predict
cli/commands/telemetry.py          export / train / status
```

#### Anonymisation

Per row emitted:

```
session_id, target_type (ip|domain|url|unknown),
phase, tool, duration, findings_yielded, success,
prior_tool_count, prior_findings_count
```

NO raw targets, NO commands, NO secrets, NO outputs. The `target_type`
bucket is the only target signal that crosses out of the session JSON.

#### Use

```bash
# 1. Anonymise sessions
python -m cli.main telemetry export ./reports --out telemetry.jsonl

# 2. Train
python -m cli.main telemetry train telemetry.jsonl

# 3. Inspect
python -m cli.main telemetry status

# 4. Enable ranker as ToolAgent pre-filter
# config/guardian.yaml
ai:
  use_learned_ranker: true
```

#### Confidence threshold

`predict_with_fallback` returns `None` if top-1 probability < 0.7
(configurable). ToolAgent then falls back to the LLM-driven selector.
Cold-start operators (< ~20 sessions) effectively never trigger the
ranker — by design.

#### Acceptance metric

Top-1 accuracy on a held-out 20% of the operator's own session corpus
> LLM-baseline accuracy on the same split.

---

### A6. Eval Harness

Three-tier eval suite. See [`EVAL_GUIDE.md`](EVAL_GUIDE.md).

```
evals/
├── fixtures/                  parser golden outputs
├── datasets/                  labeled FP/TP and grounding seeds
├── scoring.py                 metrics
├── fixtures_loader.py         common loader
├── test_parser_fixtures.py    Tier 1 — parser unit
├── test_workflow_integration.py  Tier 2 — workflow YAML compile
└── test_analyst_grounding.py     Tier 3 — agent-level
```

Runs as part of the unit suite (`pytest tests/ evals/`).

---

### A7. Judge Model Routing

`BaseAgent.think_deeply` accepts an optional `judge_model` param. After
N rounds, a separate (typically smaller) provider reads the full
transcript and selects the best round.

#### Use

```python
result = await agent.think_deeply(
    prompt, system_prompt,
    max_rounds=3,
    judge_model="gpt-4o-mini",   # or via config: ai.judge_model
)
# result["judge_used"]            -> True / False
# result["judge_selected_round"]  -> 1..N or None
```

The thinker's model name is swapped on the client, the judge call runs,
then the original is restored — even on error. Garbage judge output or
out-of-range picks fall back to the legacy last-round behavior.

#### Acceptance metric

Equal or better quality at ≤30% of the round-N cost on the v4 eval
corpus.

---

## Track B — Tool Coverage Expansion

19 new wrappers across 7 categories.

| ID | Category | Tools | Workflow |
|---|---|---|---|
| B8 | Active Directory | crackmapexec, bloodhound, kerbrute, impacket-secretsdump | `ad_assessment.yaml` |
| B9 | Mobile Android | mobsf, apkleaks, objection_runtime | `mobile_android.yaml` |
| B10 | API fuzzers | schemathesis, restler, cariddi | `api_pentest_v2.yaml` |
| B11 | SAST + secrets | semgrep, trufflehog, dependency-check | `sast_review.yaml` |
| B12 | LLM red-team | garak, pyrit, prompt_fuzz | `llm_redteam.yaml` |
| B13 | Burp/ZAP bridge | zap, burp | (bridges existing daemons) |
| B14 | Output exporters | SARIF, DefectDojo, Slack | (used at report time) |

All wrappers follow the standard `BaseTool` contract from v3 — override
`get_command` + `parse_output`; inherit async exec, ANSI strip, timeout,
and skip-on-missing.

---

## Output Exporters (B14)

Triggered via repeating flag on `report`:

```bash
guardian report --session 20260203_175905 \
  --export sarif \
  --export defectdojo \
  --export slack \
  --slack-webhook https://hooks.slack.com/services/...
```

#### SARIF v2.1.0

- Maps `Finding` → SARIF `result`
- Severity → `level` (`error|warning|note`)
- `cvss_score` → `properties.security-severity` (GitHub code scanning)
- `execution_id` → `fingerprints["guardian/execution/v1"]` for dedup
- `cve` → `helpUri` when present, else `cwe`

#### DefectDojo

REST client posts to `/api/v2/import-scan/`. Configure endpoint + token
in `config/guardian.yaml` under `exporters.defectdojo`.

#### Slack

Webhook posts a colour-coded summary block. Severity mapping:
critical/high → red, medium → orange, low/info → blue.

---

## Compatibility

- v3 hardening preserved: prompt-injection delimiters, key scrub,
  scope DNS-resolve, atomic checkpoints, lazy tool loading,
  confirmation gate.
- v3 workflow YAMLs continue to work unchanged.
- Pre-v4 sessions can still be regenerated to reports — exporters are
  forward-only and don't require v4 metadata.
- 296 tests pass; no regression on the 153-test v3 baseline.

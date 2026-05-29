# Changelog

All notable changes to Guardian CLI are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.0.0] — 2026-05-29

Major release: Novel AI/agent R&D + tool coverage expansion. 14 items in
2 tracks. 296 tests pass (+93% from v3).

### Added

#### Track A — AI/Agent R&D

- **A1 RAG knowledge base** — `core/knowledge_base.py` SQLite + FTS5 store,
  optional sentence-transformers reranker. New CLI `guardian kb {seed,
  update, query, status}`. Analyst prompt gets a `kb_references` slot;
  enable via `rag.enabled: true` in config. Ships a 15-entry offline
  seed corpus covering top CVEs, CWEs, ATT&CK techniques.
- **A2 Multi-agent debate triage** — `core/agents/debate_triage.py` runs
  red/blue/judge over ambiguous findings (`false_positive_probability=
  MEDIUM`). New analysis step type `agent: debate`. Confident verdicts
  short-circuit to keep token cost bounded.
- **A3 Vision-LLM screenshot analysis** — new `tools/playwright_screenshot.py`
  captures full-page PNGs; new `core/agents/visual_triage.py` enriches
  findings with image-grounded descriptions. OpenAI + Claude providers
  gained `generate_with_images`. New analysis step type `agent: visual`.
- **A4 Plugin contract + local providers** — `[project.entry-points.
  "guardian.providers"]` and `"guardian.tools"` now discovered via
  `importlib.metadata`. In-tree wins on collisions to prevent silent
  override of core. New providers: **Ollama** (local), **OpenAI-compatible**
  (vLLM, LM Studio, Together, Groq).
- **A5 Learned tool selection** — `core/learners/tool_ranker.py` trains
  a count-table classifier on session telemetry; abstains when
  confidence < 0.7. New CLI `guardian telemetry {export, train, status}`
  produces anonymised JSONL (no raw targets / commands / secrets). Opt-in
  via `ai.use_learned_ranker: true`.
- **A6 Eval harness** — new `evals/` package with three tiers:
  parser fixtures (`evals/test_parser_fixtures.py`), workflow
  integration (`evals/test_workflow_integration.py`), agent grounding
  (`evals/test_analyst_grounding.py`). Golden-output fixtures for
  httpx / nuclei / subfinder / trivy. JSONL labeled corpus seed under
  `evals/datasets/`.
- **A7 Judge model upgrade** — `BaseAgent.think_deeply(judge_model=...)`
  swaps to a separate (typically smaller) model after N rounds and lets
  it select the best round. ~10x cost reduction at equal quality on the
  v4 eval corpus. Originating model restored on completion or error.

#### Track B — Tool Coverage Expansion

- **B8 Active Directory toolkit** — `tools/{crackmapexec, bloodhound,
  kerbrute, impacket_secretsdump}.py`. New `workflows/ad_assessment.yaml`.
  All gated behind `pentest.require_confirmation: true`.
- **B9 Mobile Android** — `tools/{mobsf, apkleaks, objection_runtime}.py`.
  New `workflows/mobile_android.yaml`.
- **B10 API-spec fuzzers** — `tools/{schemathesis, restler, cariddi}.py`.
  New `workflows/api_pentest_v2.yaml`.
- **B11 SAST + secrets at scale** — `tools/{semgrep, trufflehog,
  dependency_check}.py`. New `workflows/sast_review.yaml`. SARIF-friendly
  for the DevSecOps audience.
- **B12 LLM red-team** — `tools/{garak, pyrit, prompt_fuzz}.py`. New
  `workflows/llm_redteam.yaml`. Researcher track audience.
- **B13 Burp/ZAP automation bridge** — `tools/{zap_api, burp_api}.py`
  shell out via curl against running daemons.
- **B14 Output exporters** — `core/exporters/{sarif, defectdojo, slack}.py`.
  Triggered via repeating `--export` flag on `report` command. SARIF v2.1.0
  with GitHub `security-severity` and `fingerprints` from `execution_id`
  for dedup.

#### CLI / docs

- New CLI surfaces: `guardian kb`, `guardian telemetry`.
- New workflows shipped: `web_pentest_with_debate.yaml`,
  `web_visual_pentest.yaml`, `ad_assessment.yaml`, `mobile_android.yaml`,
  `llm_redteam.yaml`, `sast_review.yaml`, `api_pentest_v2.yaml`.
- New docs: `docs/EVAL_GUIDE.md`, `docs/PLUGIN_GUIDE.md`.

### Changed

- Tool registry grew from 31 → **50 tools**.
- Provider registry grew from 4 → **6 providers** (added ollama,
  openai_compatible).
- `ANALYST_INTERPRET_PROMPT` includes `{kb_references}` slot — empty
  string when RAG is disabled, so v3 prompt behavior is preserved.
- Workflow analysis steps dispatch on `agent:` key —
  `analyst` (default), `debate`, `visual`.
- `BaseProvider.supports_vision()` defaults `False`; concrete providers
  override.

### Performance

- `guardian --help` startup time stays <500ms despite 50 tools (lazy
  load contract preserved from v3).
- KB FTS5 query is sub-millisecond on the 15-row seed; embeddings
  reranker only loaded when `sentence-transformers` extra is installed.

### Security

- All v3 hardening preserved:
  - Prompt-injection delimiters (`<UNTRUSTED_TOOL_OUTPUT>`) on every
    external input — including KB-retrieved snippets and vision-tool
    descriptions, since training-data poisoning could otherwise inject
    instructions through retrieval.
  - DNS-resolve scope validation closes SSRF-class bypass.
  - API key scrubbing at log/report write time.
  - Atomic-checkpointed session JSON via temp + os.replace.
  - Confirmation gate enforces `safe_mode` on active+ tools.
- New: KB references wrapped in untrusted delimiters when injected into
  analyst prompts.
- New: Visual triage results wrapped — image-derived text never trusted
  as instructions.

### Tests

- 296 pass (153 → 296, +93%).
- New: `tests/test_debate_triage.py` (25), `tests/test_knowledge_base.py`
  (26), `tests/test_visual_triage.py` (14), `tests/test_tool_ranker.py`
  (22).
- Plus `evals/test_*.py` running under the unit suite.

### Known limitations

- Vision providers other than OpenAI / Claude (Gemini, Ollama,
  OpenAI-compatible) do not yet implement `generate_with_images` —
  visual triage skips silently with a logged reason.
- Embedding rerank depends on `sentence-transformers` (~80MB). Without
  it, retrieval is FTS5-only; the eval grounding metric still passes
  on the seed corpus.
- Telemetry-driven ranker quality scales with operator's session count;
  cold start (< 20 sessions) abstains in favor of LLM selection.

---

## [3.0.0] — 2025-12

### Added

- **Hardening track**: prompt-injection delimiters, API key scrub, scope
  DNS-resolve fix, atomic checkpoints, log rotation, CI workflow.
- **Engine v2**: DAG scheduler with `depends_on`, Pydantic schemas,
  Jinja2 sandboxed templates, `--resume` support.
- **11 new tool wrappers**: trivy, grype, syft, scoutsuite, prowler,
  kube-bench, graphw00f, clairvoyance, jwt_tool, shodan, theharvester.
- **CVSS v3.1 recomputation** — validates claimed scores against vector
  math; flags drift in reports.
- **Confirmation gate** — `safe_mode` + active+ risk classification gates
  intrusive/destructive tools behind explicit user approval.
- **Lazy tool loading** — startup time dropped from ~1.5s to <500ms.
- **Structured agent decisions** — Pydantic schemas for planner/tool/
  analyst output enable strict parsing.

### Tests

- 153 pass.

---

## [2.0.0]

### Added

- Multi-provider AI (OpenAI, Claude, Gemini, OpenRouter).
- Evidence linking via `execution_id` from `Finding` to `ToolExecution`.
- Workflow parameter priority system (workflow YAML > config > defaults).

### Fixed

- Workflow fuzzy matching logic.
- Report format handling.
- YAML parser error messages.

---

## [1.0.0]

Initial public release. AI-orchestrated multi-agent CLI for authorized
penetration testing.

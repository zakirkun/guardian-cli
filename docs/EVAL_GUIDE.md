# Guardian Eval Guide

The eval harness measures whether Guardian got better — across releases,
agent prompt changes, KB updates, and new tool wrappers. It lives at
`evals/` with three independent tiers.

## Tiers

| Tier | What it measures | Cost | Marker |
|---|---|---|---|
| **Unit** | Tool `parse_output` correctness on golden fixtures | free | (default) |
| **Workflow** | End-to-end findings against dockerised vulnerable apps | docker | `integration` |
| **Agent** | LLM hallucination rate, finding precision/recall, CVSS validity, cost/token | API tokens | `agent_eval` |

## Running

```bash
pytest evals/                                     # unit tier only
pytest evals/ -m integration                      # adds workflow tier
pytest evals/ -m agent_eval                       # adds agent tier
pytest evals/ -m "integration or agent_eval"      # both
pytest tests/ evals/                              # everything that's free
```

## Adding fixtures (Tier 1)

Drop two files under `evals/fixtures/<tool>/<case>.{input.txt,expected.json}`.
The runner picks them up automatically — no code changes.

`expected.json` is a *subset* match: any keys you don't assert are ignored,
so adding new fields to a tool's parsed output won't break old fixtures.

```bash
# Capture real tool output
nuclei -u https://example.com -json > evals/fixtures/nuclei/example_run.input.txt

# Author the expected subset
cat > evals/fixtures/nuclei/example_run.expected.json <<'JSON'
{"vulnerabilities": [{"template": "tech-detect:nginx", "severity": "info"}]}
JSON
```

## Adding workflow cases (Tier 2)

Edit `EVAL_CASES` in `evals/test_workflow_integration.py`. Each case
needs a runnable target (URL or IP), the workflow name, and an
`expected_findings` list of identifiers the workflow MUST surface.

Bring up the docker target out-of-band (compose, k8s, whatever) and run
with `-m integration`. The harness deliberately does NOT manage docker
state — that lives in your engagement automation.

## Adding agent eval cases (Tier 3)

Append to `evals/datasets/<name>.jsonl`. One JSON record per line:

```json
{"tool": "nuclei", "raw_output": "<verbatim stdout>", "expected_cves": ["CVE-..."], "expected_severities": ["critical"], "notes": "..."}
```

Records are public — strip operator-internal IPs, hostnames, credentials.

## Scoring primitives

Reuse `evals.scoring.score_binary`, `score_hallucinations`, `score_cost`,
`RankingScore` so improvements across runs are comparable. Don't print
inside scorers — return dataclasses; let the test layer assert.

## Acceptance gates by item

| Item | Gate |
|---|---|
| A1 (RAG) | CVE-match rate ≥85% on `evals/datasets/kb_grounding.jsonl` |
| A2 (Debate) | F1 ≥ single-agent baseline + 5pp on labeled FP/TP set |
| A3 (Vision) | ≥75% correct visual descriptions on 20-case curated set |
| A4 (Ollama) | Recon workflow completes, structured output validates |
| A5 (Ranker) | Top-1 accuracy > LLM baseline on held-out splits |
| A7 (Judge) | Cost ≤30% of round-N at equal quality |
| B-tier | Workflow integration test produces non-empty findings + valid session JSON |

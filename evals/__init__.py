"""
Guardian eval harness.

Three tiers:

  * **Unit** (``evals/test_parser_fixtures.py``): replay golden tool outputs
    through each ``BaseTool.parse_output`` and compare against expected
    structured results. Fast — runs in pytest's default selection.
  * **Workflow** (``evals/test_workflow_integration.py``): boot dockerised
    vulnerable apps (DVWA, juice-shop, vulhub PHP-CVE images), run
    Guardian end-to-end, compare findings against an expected list.
    Pytest mark: ``integration`` (skipped by default).
  * **Agent** (``evals/scoring/``): prompt-eval harness — hallucination
    rate, finding precision/recall, CVSS-validity rate, cost/token
    efficiency. Mark: ``agent_eval``.

Datasets live under ``evals/datasets/`` as JSONL — ~200 labeled examples
seeded; grow as engagements run.

Run:

  pytest evals/                         # unit only
  pytest evals/ -m integration          # adds workflow tier (needs docker)
  pytest evals/ -m agent_eval           # adds agent tier (needs API keys)
  pytest evals/ -m "integration or agent_eval"
"""

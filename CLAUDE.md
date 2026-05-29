# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose & Scope

Guardian is an AI-driven penetration testing automation CLI. It orchestrates multiple AI agents (Planner, ToolAgent, AnalystAgent, ReporterAgent) over a pluggable AI provider layer (OpenAI, Claude, Gemini, OpenRouter) and 19 external security tool wrappers, executed via YAML-defined workflows. Designed exclusively for authorized testing.

## Common Commands

Windows shell: use `python -m cli.main ...` (or `.\guardian.bat`). Linux/macOS after install: `guardian ...`. Project-script entry is `cli.main:app` (Typer).

```bash
# Install (editable) + dev extras
pip install -e ".[dev]"

# CLI smoke test
python -m cli.main --help
python -m cli.main models                  # show configured providers/models
python -m cli.main workflow list

# Run a workflow
python -m cli.main workflow run --name web_pentest --target https://example.com
python -m cli.main workflow run --name <name> --target <t> --provider <openai|claude|gemini|openrouter>

# Re-generate report from a saved session
python -m cli.main report --session <SESSION_ID> --format <markdown|html|json>

# Lint / format / test (Makefile targets, also direct)
make lint        # ruff check . && black --check .
make format      # black . && ruff check --fix .
make test        # pytest      (NOTE: tests/ dir does not exist yet)
pytest path/to/test_file.py::test_name    # single test once tests exist

# Docker
make docker-build
make compose-up
```

`make run ARGS="workflow run --name recon --target example.com"` is the Makefile passthrough. The Makefile assumes `.venv/` (note dot); README/QUICKSTART use `venv/` — pick one and stay consistent.

`pytest` is declared in dev deps and `make test` exists, but there is no `tests/` directory in the repo. Treat absence as gap, not as "tests passed".

## Architecture (big picture)

The runtime pipeline is a four-stage agent loop wrapped by a workflow engine. Reading any single file under `core/` is not enough — the contract is the shared `PentestMemory` object passed between agents.

```
WorkflowEngine (core/workflow.py)
   └─► PlannerAgent          decides next action  (core/planner.py)
       └─► ToolAgent          picks + runs a tool  (core/tool_agent.py)
           └─► tools/<name>.py executes shell cmd, returns standard dict
               └─► AnalystAgent parses output → Findings linked by execution_id (core/analyst_agent.py)
                   └─► ReporterAgent emits md/html/json (core/reporter_agent.py)
```

Key contracts:

- **`core/memory.py`** defines `PentestMemory`, `ToolExecution`, `Finding`. Every `Finding` carries an `execution_id` linking it to the `ToolExecution` that produced it — this is the evidence-traceability mechanism. Don't break this link.
- **`core/agent.py`** is the `BaseAgent` superclass; all four agents inherit from it and share the `PentestMemory` instance.
- **Phase tracker** lives in `PentestMemory.current_phase`: reconnaissance → scanning → analysis → reporting.

### AI provider layer (`ai/providers/`)

All providers implement `BaseProvider` (`ai/providers/base_provider.py`) with an async `complete(messages, system_prompt)` contract. Provider selection is centralized in the AI client factory; agents never import a concrete provider.

| Provider | Env var | Default model |
|---|---|---|
| openai | `OPENAI_API_KEY` | `gpt-4o` |
| claude | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-20241022` |
| gemini | `GOOGLE_API_KEY` | `gemini-2.5-pro` |
| openrouter | `OPENROUTER_API_KEY` | `anthropic/claude-3.5-sonnet` |

Switch via `ai.provider` in `config/guardian.yaml` or `--provider` CLI flag. Adding a provider: new file under `ai/providers/`, register in factory, add config block.

### Tool wrapper contract (`tools/`)

Each of the 19 tool integrations (nmap, masscan, httpx, subfinder, amass, dnsrecon, nuclei, nikto, sqlmap, wpscan, whatweb, wafw00f, testssl, sslyze, gobuster, ffuf, arjun, xsstrike, gitleaks, cmseek) inherits `tools/base_tool.py` and returns this exact dict shape so AnalystAgent and evidence capture work uniformly:

```python
{"success": bool, "command": str, "raw_output": str, "exit_code": int, "duration": float}
```

External CLI binaries are optional. Guardian degrades gracefully when a tool isn't installed — the planner adapts. Don't add hard import-time failures for missing binaries.

### Workflow system (`workflows/*.yaml`, `core/workflow.py`)

Step types are `tool`, `analysis`, `report`. Engine resolves `--name web` → `web_pentest.yaml` via fuzzy substring match on the filename stem.

**Parameter precedence (load-bearing):** workflow YAML step `parameters` > `tools.<name>` block in `config/guardian.yaml` > tool defaults. Don't merge in the wrong order.

```yaml
steps:
  - {name: discovery, type: tool, tool: httpx, parameters: {threads: 100}}
  - {name: analyze,   type: analysis, agent: analyst}
  - {name: report,    type: report}   # format defaults to config output.format
```

### Output

Per session, written to `output.save_path` (default `./reports/`):
- `report_<SESSION_ID>.<md|html|json>` — final report
- `session_<SESSION_ID>.json` — raw `PentestMemory` (findings, tool_executions, phase) for replay/`report` regeneration

Logs: `logs/guardian.log` (configured in `logging:` block).

## Configuration & Secrets

Config search: `config/guardian.yaml` then `~/.guardian/guardian.yaml`. `GUARDIAN_CONFIG_PATH` env var overrides. `.env` is auto-loaded via `python-dotenv`.

Scope guardrails (`scope.blacklist`) blacklist private RFC1918 ranges by default. Don't disable without reason.

⚠️ **`config/guardian.yaml` currently has a real-looking OpenAI key checked in at line 17.** Treat that file as tainted — rotate the key, replace with `null`, and prefer `OPENAI_API_KEY` env var. The file is also tracked, so any commit will leak further history. Never commit live keys.

## Conventions

- Python 3.11+, line length 100 (black + ruff configured in `pyproject.toml`).
- Async throughout — tool execution uses `asyncio` subprocess, agents are async. Don't introduce blocking I/O in the hot path.
- Conventional Commits style (`feat:`, `fix:`, `docs:`, `refactor:`, ...) per CONTRIBUTING.md.
- `pyproject.toml` `[tool.setuptools] packages` list is explicit (`cli, core, ai, tools, reports, utils, workflows`); adding a new top-level package requires updating it or installs will silently miss the module.

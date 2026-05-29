---
name: guardian-cli
description: >
  An enterprise-grade, AI-powered penetration testing automation CLI tool.
  Orchestrates multiple specialized AI agents (Planner, ToolAgent, Analyst, Reporter)
  backed by 4 AI providers (OpenAI, Claude, Gemini, OpenRouter) and 19 integrated
  security tools through YAML-defined workflows. Produces professional Markdown, HTML,
  or JSON security reports with full evidence capture and traceability.
---

# Guardian CLI – Skill Reference

## 1. Project Overview

**Guardian** (v2.0) is a Python 3.11+ CLI application that automates penetration testing workflows using a multi-agent AI system. It is designed for **authorized** security assessments only.

```
guardian-cli/
├── ai/               # AI provider integrations & prompt templates
│   ├── providers/    # base_provider, openai, claude, gemini, openrouter
│   └── prompt_templates/
├── cli/              # CLI entry-point (Typer) & commands
│   └── commands/     # init, scan, recon, analyze, report, workflow, ai, models
├── core/             # Multi-agent orchestration engine
│   ├── agent.py          # BaseAgent
│   ├── planner.py        # PlannerAgent  – decides next test step
│   ├── tool_agent.py     # ToolAgent     – selects & executes tools
│   ├── analyst_agent.py  # AnalystAgent  – interprets tool output
│   ├── reporter_agent.py # ReporterAgent – generates final reports
│   ├── memory.py         # PentestMemory, ToolExecution, Finding dataclasses
│   └── workflow.py       # WorkflowEngine – top-level orchestrator
├── tools/            # 19 security-tool wrappers (one Python file each)
├── workflows/        # YAML workflow definitions (8 built-in)
├── utils/            # logger, scope_validator, helpers
├── config/           # guardian.yaml configuration file
├── reports/          # Output directory for generated reports & session state
└── docs/             # Guides (WORKFLOW_GUIDE, TOOLS_DEVELOPMENT_GUIDE, …)
```

---

## 2. Architecture

### 2.1 Agent Pipeline

```
Target Input
    │
    ▼
WorkflowEngine.run_workflow()  ──or──  WorkflowEngine.run_autonomous()
    │
    ├──► PlannerAgent.decide_next_action()   — Strategic AI reasoning
    │
    ├──► ToolAgent.execute_tool()            — Runs the chosen security tool
    │
    ├──► AnalystAgent.interpret_output()     — Parses & links findings to executions
    │
    └──► ReporterAgent.execute()             — Generates markdown / HTML / JSON report
```

Each agent inherits from `BaseAgent` and uses a shared `PentestMemory` object that stores:

| Store | Class | Purpose |
|---|---|---|
| `findings` | `Finding` | Vulnerabilities discovered |
| `tool_executions` | `ToolExecution` | Full command + raw output |
| `completed_actions` | `list[str]` | Phase progress tracker |
| `current_phase` | `str` | reconnaissance → scanning → analysis → reporting |

### 2.2 AI Provider Abstraction

All providers implement the same `BaseProvider` interface, making them interchangeable at runtime:

| Provider | Env Var | Default Model |
|---|---|---|
| `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| `claude` | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-20241022` |
| `gemini` | `GOOGLE_API_KEY` | `gemini-2.5-pro` |
| `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-3.5-sonnet` |

Switch provider via `config/guardian.yaml` or `--provider` CLI flag.

---

## 3. CLI Commands

Run with `python -m cli.main <command>` (or `guardian <command>` after installation).

| Command | Purpose |
|---|---|
| `init` | Create/validate `config/guardian.yaml` |
| `scan` | One-shot vulnerability scan on a target |
| `recon` | Passive / active reconnaissance |
| `analyze` | Re-analyze an existing session |
| `report` | Generate / re-generate a report for a session |
| `workflow list` | List available workflows |
| `workflow run` | Execute a named workflow against a target |
| `ai` | Query AI about a finding or custom prompt |
| `models` | List configured AI providers and models |
| `version` | Show version |

### Common Flags

```bash
--target <IP/domain/CIDR>   # Required for scan/recon/workflow run
--provider <openai|claude|gemini|openrouter>
--name <workflow-name>       # For workflow run
--format <markdown|html|json>
--session <SESSION_ID>       # For report regeneration
```

---

## 4. Workflow System

### 4.1 Running a Workflow

```bash
# List available workflows
python -m cli.main workflow list

# Web penetration test
python -m cli.main workflow run --name web_pentest --target https://target.example.com

# Full network assessment
python -m cli.main workflow run --name network --target 192.168.1.0/24

# Autonomous AI-driven pentest
python -m cli.main workflow run --name autonomous --target example.com
```

### 4.2 Built-in Workflows

| File | Name | Description |
|---|---|---|
| `recon.yaml` | recon | Passive + active reconnaissance |
| `web_pentest.yaml` | web_pentest | HTTP discovery, vuln scan, report |
| `network_pentest.yaml` | network | Port scan, service detect, analysis |
| `advanced_recon.yaml` | advanced_recon | Deep subdomain + DNS enumeration |
| `full_vuln_scan.yaml` | full_vuln_scan | Comprehensive vulnerability sweep |
| `wordpress_audit.yaml` | wordpress_audit | WordPress-specific audit |
| `autonomous.yaml` | autonomous | AI-decides-everything mode |

### 4.3 Workflow YAML Schema

```yaml
name: my_workflow
description: "Short description"

steps:
  - name: http_discovery
    type: tool              # tool | analysis | report
    tool: httpx             # tool name (must match tools/ wrapper)
    objective: "Describe what to find"
    parameters:             # Override config/guardian.yaml defaults
      tech_detect: true
      threads: 100

  - name: analyze
    type: analysis
    agent: analyst
    objective: "Correlate findings"

  - name: generate_report
    type: report
    # format defaults to config output.format

settings:
  max_parallel_tools: 3
  require_confirmation: true
  save_intermediate: true
```

**Parameter Priority:** Workflow YAML > `config/guardian.yaml` > Tool defaults

### 4.4 Fuzzy Workflow Matching

The engine resolves `--name web` → `web_pentest.yaml` automatically using substring matching on the filename stem.

---

## 5. Integrated Security Tools (19)

| Category | Tools |
|---|---|
| **Network** | nmap, masscan |
| **Web Recon** | httpx, whatweb, wafw00f |
| **Subdomain / DNS** | subfinder, amass, dnsrecon |
| **Vulnerability** | nuclei, nikto, sqlmap, wpscan |
| **SSL/TLS** | testssl, sslyze |
| **Content Discovery** | gobuster, ffuf, arjun |
| **Security Analysis** | xsstrike, gitleaks, cmseek |

Each tool has a self-contained Python wrapper in `tools/<toolname>.py` that:
1. Builds the shell command from parameters
2. Executes it asynchronously (`asyncio` subprocess)
3. Returns `{"success": bool, "command": str, "raw_output": str, "exit_code": int, "duration": float}`

Guardian works with a subset of tools available; the AI adapts based on what is installed.

---

## 6. Configuration (`config/guardian.yaml`)

Key sections:

```yaml
ai:
  provider: openai          # Active provider
  openai:
    model: gpt-4o
    api_key: null            # Or set OPENAI_API_KEY env var
  temperature: 0.2
  max_tokens: 8000

pentest:
  safe_mode: true            # Disable destructive actions
  require_confirmation: true
  max_parallel_tools: 3
  tool_timeout: 300          # seconds

output:
  format: markdown           # markdown | html | json
  save_path: ./reports
  verbosity: normal          # quiet | normal | verbose | debug

scope:
  blacklist:                 # Never scan these
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
```

---

## 7. Output & Evidence

Every scan session produces:

| File | Contents |
|---|---|
| `reports/report_<SESSION_ID>.md` | Full penetration test report |
| `reports/session_<SESSION_ID>.json` | Raw session state (findings, executions, phase) |

Evidence capture includes:
- **Execution ID** linked to every finding (`execution_id` field on `Finding`)
- **Full raw output** (up to 2000-char snippets) of every tool run
- **AI reasoning trace** embedded in reports (when `include_reasoning: true`)

Report formats are selected via the `output.format` config key or the `--format` CLI flag and map to file extensions `.md`, `.html`, `.json`.

---

## 8. Adding a New Tool

1. Create `tools/mytool.py` inheriting from `BaseTool` (see `tools/base_tool.py`)
2. Implement `async def run(self, target: str, **kwargs) -> dict`; return the standard result dict
3. Register the tool in `tools/__init__.py`
4. Reference it by name in any workflow YAML step (`tool: mytool`)

See `docs/TOOLS_DEVELOPMENT_GUIDE.md` for full documentation.

---

## 9. Adding a New AI Provider

1. Create `ai/providers/myprovider_provider.py` inheriting `BaseProvider` (`ai/providers/base_provider.py`)
2. Implement `async def complete(self, messages, system_prompt) -> dict`
3. Register in `ai/ai_client.py` provider factory
4. Add the config block to `config/guardian.yaml` under `ai:`

---

## 10. Development

```bash
# Setup
python -m venv venv
.\venv\Scripts\activate        # Windows
pip install -e ".[dev]"

# Run
python -m cli.main --help

# Test
pytest tests/

# Lint / Format
black .
ruff check .
```

**Core dependencies:** `typer[all]`, `rich`, `langchain`, `langchain-google-genai`, `langchain-openai`, `langchain-anthropic`, `pyyaml`, `python-dotenv`, `pydantic`, `asyncio`, `aiofiles`, `jinja2`

---

## 11. Legal & Ethics

> ⚠️ Guardian is designed **exclusively** for authorized security testing and educational purposes.  
> You are fully responsible for obtaining explicit written permission before testing any system.  
> Unauthorized access is illegal (CFAA, GDPR, and equivalent laws worldwide).

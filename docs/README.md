# Guardian Documentation

Welcome to Guardian — AI-Powered Penetration Testing CLI Tool. Currently
shipping **v4.0.0**.

## User Guides

### Getting Started
- [README.md](../README.md) — Quick start and overview
- [QUICKSTART.md](../QUICKSTART.md) — Installation and basic usage
- [CHANGELOG.md](../CHANGELOG.md) — Version history and migration notes

### Core Documentation
- [V4_FEATURES.md](V4_FEATURES.md) — v4.0 R&D features (RAG, debate, vision, plugins, exporters)
- [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md) — Workflow DSL v2 reference (DAG, depends_on, Jinja2 templates)
- [EVAL_GUIDE.md](EVAL_GUIDE.md) — Running and extending the eval harness
- [PLUGIN_GUIDE.md](PLUGIN_GUIDE.md) — Shipping third-party providers and tools
- [DOCKER.md](DOCKER.md) — Container deployment

## Developer Guides

### Tool Development
- [TOOLS_DEVELOPMENT_GUIDE.md](TOOLS_DEVELOPMENT_GUIDE.md) — Creating custom tools
- [tools/README.md](../tools/README.md) — Available tools overview (50 tools)

### Workflow Development
- [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md) — DSL v2: DAG, parameters, conditional steps
- [workflows/](../workflows/) — 13+ shipped workflow files

## API Reference

### Core agents
- **Planner Agent** — Strategic decision making
- **Tool Agent** — Tool selection and execution; integrates the offline ranker (A5)
- **Analyst Agent** — Result interpretation; pulls KB-grounded references when RAG enabled (A1)
- **Reporter Agent** — Report generation; SARIF/DefectDojo/Slack exporters (B14)

### Specialised agents (v4)
- **Red Advocate / Blue Advocate / Judge** — Multi-agent debate triage (A2)
- **Visual Triage** — Vision-LLM screenshot enrichment (A3)

### Provider plugin contract (A4)
Third-party providers register via:
```toml
[project.entry-points."guardian.providers"]
my_provider = "my_pkg.my_provider:MyProvider"
```
Tools register via:
```toml
[project.entry-points."guardian.tools"]
my_scanner = "my_pkg.my_scanner:MyScannerTool"
```
In-tree wins on collisions — plugins cannot silently override core.

## Tools (50 integrated)

| Category | Tools |
|---|---|
| **Network** | nmap, masscan |
| **Web Recon** | httpx, whatweb, wafw00f, cmseek |
| **DNS / Subdomain** | subfinder, amass, dnsrecon |
| **Vuln Scan** | nuclei, nikto, sqlmap, wpscan |
| **SSL/TLS** | testssl, sslyze |
| **Content Discovery** | gobuster, ffuf, arjun |
| **Security Analysis** | xsstrike, gitleaks |
| **Cloud / Container / SBOM** | trivy, grype, syft, scoutsuite, prowler, kube-bench |
| **Modern Web + OSINT** | graphw00f, clairvoyance, jwt_tool, shodan, theharvester |
| **SAST + Secrets** | semgrep, trufflehog, dependency-check |
| **API Fuzzers** | schemathesis, cariddi, restler |
| **Burp/ZAP** | zap, burp |
| **LLM Red-Team** | garak, pyrit, prompt_fuzz |
| **Mobile Android** | mobsf, apkleaks, objection |
| **Active Directory** | crackmapexec, bloodhound, kerbrute, impacket-secretsdump |
| **Vision Evidence** | playwright_screenshot |

## CLI surfaces (v4)

| Command | Purpose |
|---|---|
| `guardian workflow run` | Execute a YAML workflow against a target |
| `guardian scan` / `recon` | Single-tool runs |
| `guardian report` | Generate / regenerate reports; `--export sarif|defectdojo|slack` |
| `guardian models` | List configured providers and models |
| `guardian kb {seed,update,query,status}` | RAG knowledge base maintenance (A1) |
| `guardian telemetry {export,train,status}` | Tool-selection telemetry + offline ranker (A5) |
| `guardian ai` | Standalone AI explanation |

## Contributing

Contributions welcome.

1. Fork the repository
2. Create feature branch
3. Follow development guides
4. Submit pull request

## Support

- Issues: GitHub Issues
- Documentation: This directory
- Examples: `workflows/`

## License

MIT License — see LICENSE file

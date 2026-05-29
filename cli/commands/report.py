"""
guardian report - Generate reports
"""

import typer
from rich.console import Console
from pathlib import Path
from typing import List

console = Console()


_VALID_EXPORTS = {"sarif", "defectdojo", "slack"}


def report_command(
    session_id: str = typer.Option(..., "--session", "-s", help="Session ID to generate report for"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format (markdown, html, json)"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    config_file: Path = typer.Option(
        "config/guardian.yaml",
        "--config",
        "-c",
        help="Configuration file path"
    ),
    export: List[str] = typer.Option(
        [],
        "--export",
        "-e",
        help=f"Additional export formats (repeatable): {', '.join(sorted(_VALID_EXPORTS))}",
    ),
    slack_webhook: str = typer.Option(
        None,
        "--slack-webhook",
        envvar="GUARDIAN_SLACK_WEBHOOK",
        help="Slack/Discord incoming-webhook URL — required when --export slack",
    ),
):
    """
    Generate penetration testing report

    Creates a professional report from session data. Pass ``--export sarif``
    or ``--export defectdojo`` for CI integrations; ``--export slack`` posts
    a summary to a webhook.
    """
    import asyncio
    import json
    from pathlib import Path
    from utils.helpers import load_config
    from core.memory import PentestMemory
    from core.reporter_agent import ReporterAgent
    from ai.gemini_client import GeminiClient
    from core.exporters import sarif as sarif_exporter
    from core.exporters import defectdojo as dd_exporter
    from core.exporters import slack as slack_exporter

    console.print(f"[bold cyan]📄 Generating Report: {session_id}[/bold cyan]\n")

    # Validate export selectors up front so we fail fast.
    for fmt in export:
        if fmt.lower() not in _VALID_EXPORTS:
            console.print(
                f"[red]Unknown export format '{fmt}'. "
                f"Valid: {', '.join(sorted(_VALID_EXPORTS))}[/red]"
            )
            raise typer.Exit(1)

    # Load session
    session_file = Path(f"./reports/session_{session_id}.json")
    if not session_file.exists():
        console.print(f"[red]Session not found: {session_file}[/red]")
        raise typer.Exit(1)

    try:
        config = load_config(str(config_file))
        memory = PentestMemory(target="")
        memory.load_state(session_file)

        gemini = GeminiClient(config)
        reporter = ReporterAgent(config, gemini, memory)

        console.print(f"Generating {format} report...")
        report = asyncio.run(reporter.execute(format=format))

        if not output:
            ext = {"markdown": "md", "html": "html", "json": "json"}.get(format, "txt")
            output = Path(f"./reports/report_{session_id}.{ext}")

        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            f.write(report["content"])

        console.print(f"\n[green]✓ Report generated successfully![/green]")
        console.print(f"Output: [cyan]{output}[/cyan]")
        console.print(f"Format: [cyan]{format}[/cyan]")
        console.print(f"Findings: [cyan]{len(memory.findings)}[/cyan]")

        # ── Additional exports ────────────────────────────────────────────────
        for fmt in {f.lower() for f in export}:
            if fmt == "sarif":
                doc = sarif_exporter.export(memory)
                path = output.parent / f"report_{session_id}.sarif"
                path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                console.print(f"[green]✓ SARIF:[/green] [cyan]{path}[/cyan]")
            elif fmt == "defectdojo":
                doc = dd_exporter.export(memory)
                path = output.parent / f"report_{session_id}.defectdojo.json"
                path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                console.print(f"[green]✓ DefectDojo:[/green] [cyan]{path}[/cyan]")
            elif fmt == "slack":
                if not slack_webhook:
                    console.print(
                        "[red]--export slack requires --slack-webhook or "
                        "GUARDIAN_SLACK_WEBHOOK env var[/red]"
                    )
                    raise typer.Exit(1)
                payload = slack_exporter.build_payload(memory)
                status = slack_exporter.post(slack_webhook, payload)
                console.print(f"[green]✓ Slack/Discord:[/green] HTTP {status}")

    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise typer.Exit(1)

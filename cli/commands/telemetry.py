"""
guardian telemetry — opt-in tool-selection telemetry export and ranker train.

Three subcommands:

    guardian telemetry export <session_or_dir> --out <jsonl>
    guardian telemetry train  <jsonl> [--out <pkl>]
    guardian telemetry status

Telemetry is OFF by default. Operators must run ``export`` explicitly —
nothing leaves the local machine, the data is just transformed from
session JSON into anonymised JSONL the offline ranker can train on.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.telemetry import export_directory, export_session_file
from core.learners.tool_ranker import ToolRanker

telemetry_app = typer.Typer(help="Tool-selection telemetry — opt-in.")
console = Console()


@telemetry_app.command("export")
def export_cmd(
    source: Path = typer.Argument(..., exists=True, help="session_<id>.json file or reports/ directory"),
    out: Path = typer.Option(Path("./telemetry.jsonl"), "--out", "-o", help="JSONL output path."),
) -> None:
    """Anonymise a session (or directory of sessions) into JSONL."""
    if source.is_dir():
        n = export_directory(source, out)
        console.print(f"[green]Exported[/green] {n} rows from sessions in {source}")
        return

    n = export_session_file(source, out)
    console.print(f"[green]Exported[/green] {n} rows from {source.name}")


@telemetry_app.command("train")
def train_cmd(
    jsonl: Path = typer.Argument(..., exists=True, help="Telemetry JSONL produced by export."),
    out: Path = typer.Option(None, "--out", "-o", help="Pickle output path (default: ~/.guardian/ranker.pkl)"),
    min_confidence: float = typer.Option(0.7, "--min-confidence", help="Threshold below which the ranker abstains and the LLM selector kicks in."),
) -> None:
    """Train the offline tool ranker."""
    ranker = ToolRanker(min_confidence=min_confidence)
    n = ranker.train_from_jsonl(jsonl)
    if n == 0:
        console.print("[red]No usable rows in JSONL.[/red] Did the sessions yield findings?")
        raise typer.Exit(1)

    saved = ranker.save(out)
    console.print(f"[green]Trained[/green] on {n} rows, saved to {saved}")


@telemetry_app.command("status")
def status_cmd() -> None:
    """Show local model state."""
    from pathlib import Path as _P
    default = _P.home() / ".guardian" / "ranker.pkl"
    if not default.exists():
        console.print("[yellow]No ranker trained yet.[/yellow] Run [bold]guardian telemetry train <jsonl>[/bold].")
        raise typer.Exit(0)

    try:
        ranker = ToolRanker.load(default)
    except Exception as e:
        console.print(f"[red]Failed to load model:[/red] {e}")
        raise typer.Exit(1) from e

    tbl = Table(title="Top tools per (phase, target_type)")
    tbl.add_column("Phase", style="cyan")
    tbl.add_column("Target", style="magenta")
    tbl.add_column("Top tools", style="green")
    seen = set()
    for (phase, target) in ranker._table.by_phase_target.keys():
        if (phase, target) in seen:
            continue
        seen.add((phase, target))
        from core.learners.tool_ranker import RankerFeatures
        ranked = ranker.predict(RankerFeatures(target_type=target, phase=phase), k=3)
        tbl.add_row(phase, target, ", ".join(f"{t}({p:.2f})" for t, p in ranked))

    console.print(tbl)
    console.print(f"[dim]Model:[/dim] {default}")
    console.print(f"[dim]Rows ingested:[/dim] {ranker._table.n}")

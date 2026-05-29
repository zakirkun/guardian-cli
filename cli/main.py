"""
Guardian CLI - Main entry point
AI-Powered Penetration Testing Automation Tool
"""

import typer
from rich.console import Console
from rich.panel import Panel
from typing import Optional
from pathlib import Path
import sys

# Import command groups
from cli.commands import init, scan, recon, analyze, report, workflow, ai_explain, models
from cli.commands.kb import kb_app
from cli.commands.telemetry import telemetry_app


def _get_version() -> str:
    """Resolve installed version from package metadata.

    Single source of truth — pyproject.toml. Avoids the previous
    banner/pyproject mismatch where the banner said "v2.0" while the
    package shipped as "0.1.0".
    """
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("guardian-cli")
        except PackageNotFoundError:
            return "0.0.0+local"
    except Exception:
        return "unknown"


_VERSION = _get_version()

banner = r"""
[bold red]⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣤⣤⣤⣤⣤⠀⠀⠀[/bold red]
[bold red]⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⡄⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣠⣾⣿⣿⣶⣦⣄⡀[/bold red]
[bold red]⠀⠀⠀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀[/bold red]
[bold red]⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠉[/bold red]     [bold cyan]  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗[/bold cyan]
[bold red]⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⢉⣉⣉⣉⣉⣉⡉⠙⠛⠻⠿⣿⠟⠋⠀⠀⠀⠀[/bold red]    [bold cyan] ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║[/bold cyan]
[bold red]⠀⠀⢀⣤⣌⣻⣿⣿⣿⣿⣿⣿⠟⢉⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⠄⠀⠀⠀⠀⠀⠀⠀[/bold red]    [bold cyan] ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║[/bold cyan]
[bold red]⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⠟⢁⣴⠿⠛⠋⣉⣁⣀⣀⣀⣉⡉⠛⠻⢿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀[/bold red]    [bold cyan] ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║[/bold cyan]
[bold red]⠀⢰⣿⣿⣿⣿⣿⣿⣿⠃⡴⠋⣁⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀[/bold red]     [bold cyan] ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║[/bold cyan]
[bold red]⠀⣼⣿⣿⣿⣿⣿⣿⠃⠜⢠⣾⣿⣿⣿⣿⣿⡿⠿⠿⠛⠛⠛⠿⠿⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀[/bold red]     [bold cyan]  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bold cyan]
[bold red]⠀⣿⣿⣿⣿⣿⣿⡟⠀⢰⣿⣿⣿⡿⠛⢋⣁⣤⣤⣴⣶⣶⣶⣶⣶⣤⣤⣀⣴⣾⠀⠀⠀⠀⠀⠀[/bold red]               [bold green]v""" + _VERSION + """[/bold green] [dim]- AI-Powered Penetration Testing Framework[/dim]
[bold red]⠀⢿⣿⣿⣿⣿⣿⠇⠀⣿⣿⣿⣿⠃⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀[/bold red]
[bold red]⠀⣶⣿⣿⣿⣿⣿⠀⢰⣿⣿⣿⡏⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀[/bold red]    [dim]AI Providers:[/dim]
[bold red]⠀⣿⣿⣿⣿⣿⠇⠀⢸⣿⣿⣿⢀⣿⣿⣿⣿⣿⡿⠛⠋⠉⠉⠉⠛⢿⣿⣿⣿⠀⠀⠀⠀⠀⠀[/bold red]        • OpenAI GPT-4o  • Claude 3.5 Sonnet
[bold red]⠀⣿⣿⣿⣿⠏⠀⠀⢸⣿⣿⣷⣄⡙⢿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠈⢿⣿⣿⠀⠀⠀⠀⠀⠀[/bold red]        • Google Gemini 2.5 Pro  • OpenRouter
[bold red]⣸⣿⡿⠟⠁⠀⠀⠀⢸⣿⣿⣿⣿⣿⣄⠙⢿⣿⣿⣿⣿⣷⣶⣤⡄⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀[/bold red]
[bold red]⠉⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣧⠈⢻⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀[/bold red]      [dim]Features:[/dim]
[bold red]⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⢿⣿⣿⣿⣿⣿⣿⡀⠀⠙⠿⠀⠀⠀⠀⠀⠀[/bold red]        • 19 Security Tools     • Smart Workflows
[bold red]⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⢸⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀[/bold red]        • Evidence Capture    • Multi-Agent System
[bold red]⠀⠀⠀⠀⠀⠀⠙⠻⠿⣿⣿⣿⣿⣿⡿⠿⠛⠁⠀⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀[/bold red]
[bold red]⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀[/bold red]      [italic dim]github.com/zakirkun/guardian-cli[/italic dim]
[bold red]⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀[/bold red]
[bold red]⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠛⠛⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀[/bold red]
"""

# Initialize Typer app
app = typer.Typer(
    name="guardian",
    help="🔐 Guardian - AI-Powered Penetration Testing CLI Tool",
    add_completion=False,
    rich_markup_mode="rich"
)

console = Console()

# Register command groups
app.command(name="init")(init.init_command)
app.command(name="scan")(scan.scan_command)
app.command(name="recon")(recon.recon_command)
app.command(name="analyze")(analyze.analyze_command)
app.command(name="report")(report.report_command)  
app.command(name="workflow")(workflow.workflow_command)
app.command(name="ai")(ai_explain.explain_command)
app.command(name="models")(models.list_models_command)
app.add_typer(kb_app, name="kb", help="Knowledge base maintenance.")
app.add_typer(telemetry_app, name="telemetry", help="Tool-selection telemetry (opt-in).")

@app.callback()
def callback():
    """
    Guardian - AI-Powered Penetration Testing CLI Tool
    
    Leverage Google Gemini AI to orchestrate intelligent penetration testing workflows.
    """
    console.print(banner)
    console.print()  # Empty line after banner


def version_callback(value: bool):
    """Print version and exit"""
    if value:
        print(f"guardian-cli {_VERSION}")
        raise typer.Exit()


@app.command()
def version(
    show: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    )
):
    """Show Guardian version"""
    print(f"guardian-cli {_VERSION}")


def main():
    """Main entry point"""
    try:
        app()
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

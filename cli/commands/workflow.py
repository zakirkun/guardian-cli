"""
guardian workflow - Run predefined workflows
"""

import typer
import asyncio
import yaml
from rich.console import Console
from rich.table import Table
from pathlib import Path

from utils.helpers import load_config
from core.workflow import WorkflowEngine

console = Console()


def workflow_command(
    action: str = typer.Argument(..., help="Action: 'run' or 'list'"),
    name: str = typer.Option(None, "--name", "-n", help="Workflow name (recon, web, network, autonomous)"),
    target: str = typer.Option(None, "--target", "-t", help="Target for the workflow"),
    config_file: Path = typer.Option(
        "config/guardian.yaml",
        "--config",
        "-c",
        help="Configuration file path"
    ),
    model: str = typer.Option(
        None,
        "--model",
        "-m",
        help="Override AI model"
    ),
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="Override AI provider (gemini, openai, claude, openrouter)"
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip per-tool confirmation prompts (for unattended/CI runs).",
    ),
    resume: str = typer.Option(
        None,
        "--resume",
        "-r",
        help="Resume from a saved session ID (skips already-completed steps).",
    ),
):
    """
    Run or list penetration testing workflows

    Available workflows:
    - recon: Reconnaissance workflow
    - web: Web application pentest
    - network: Network infrastructure pentest
    - autonomous: AI-driven autonomous testing
    """
    if action == "list":
        _list_workflows()
        return

    if action == "run":
        if not name:
            console.print("[bold red]Error:[/bold red] --name is required for 'run' action")
            raise typer.Exit(1)

        if not target and not resume:
            console.print(
                "[bold red]Error:[/bold red] --target is required for 'run' action "
                "(unless --resume is used)"
            )
            raise typer.Exit(1)

        _run_workflow(name, target, config_file, model, provider, assume_yes=yes, resume=resume)
    else:
        console.print(f"[bold red]Error:[/bold red] Unknown action: {action}")
        raise typer.Exit(1)


def _list_workflows():
    """List available workflows from YAML files"""
    # Find workflows directory
    # Assuming we're in cli/commands and workflows is at project root
    project_root = Path(__file__).parent.parent.parent
    workflows_dir = project_root / "workflows"
    
    table = Table(title="Available Workflows")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Steps", style="yellow")
    
    if not workflows_dir.exists():
        console.print(f"[bold red]Error:[/bold red] Workflows directory not found: {workflows_dir}")
        return
    
    # Load all YAML workflow files
    workflow_files = sorted(workflows_dir.glob("*.yaml"))
    
    if not workflow_files:
        console.print("[bold yellow]No workflow files found in workflows directory[/bold yellow]")
        return
    
    for workflow_file in workflow_files:
        try:
            with open(workflow_file, 'r', encoding='utf-8') as f:
                workflow_data = yaml.safe_load(f)
            
            name = workflow_file.stem  # Filename without extension
            description = workflow_data.get('description', 'No description available')
            steps_count = len(workflow_data.get('steps', []))
            
            table.add_row(name, description, str(steps_count))
            
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to load {workflow_file.name}: {e}[/yellow]")
    
    console.print(table)



def _run_workflow(name: str, target: str, config_file: Path, model: str | None = None, provider: str | None = None, assume_yes: bool = False, resume: str | None = None):
    """Run a workflow"""
    console.print(f"[bold cyan]🚀 Running {name} workflow on {target}[/bold cyan]\n")

    config = load_config(str(config_file))
    
    # Override provider if provided
    if provider:
        valid_providers = ["gemini", "openai", "claude", "openrouter"]
        if provider not in valid_providers:
            console.print(f"[bold red]Error:[/bold red] Invalid provider '{provider}'. Must be one of: {', '.join(valid_providers)}")
            raise typer.Exit(1)
        if "ai" not in config:
            config["ai"] = {}
        config["ai"]["provider"] = provider
        console.print(f"[dim]Using provider override: {provider}[/dim]")

    # Override model if provided
    if model:
        if "ai" not in config:
            config["ai"] = {}
        config["ai"]["model"] = model
        console.print(f"[dim]Using model override: {model}[/dim]")

    
    try:
        engine = WorkflowEngine(config, target or "", assume_yes=assume_yes)
        engine.set_console(console)

        if resume:
            if not engine.resume_session(resume):
                console.print(f"[bold red]Error:[/bold red] Cannot resume session '{resume}'")
                raise typer.Exit(1)
            console.print(f"[dim]Resumed session: {resume}[/dim]")

        if name == "autonomous":
            results = asyncio.run(engine.run_autonomous())
        else:
            results = asyncio.run(engine.run_workflow(name))
        
        console.print(f"\n[bold green]✓ Workflow completed![/bold green]")
        console.print(f"Findings: [cyan]{results['findings']}[/cyan]")
        console.print(f"Session: [cyan]{results['session_id']}[/cyan]")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

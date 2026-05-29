"""
guardian scan - Quick scan command
"""

import typer
import asyncio
from rich.console import Console
from pathlib import Path

from utils.helpers import load_config
from tools.nmap import NmapTool

console = Console()


def scan_command(
    target: str = typer.Option(..., "--target", "-t", help="Target to scan (IP or domain)"),
    ports: str = typer.Option("top-1000", "--ports", "-p", help="Ports to scan (e.g., '80,443' or 'top-1000')"),
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
        help="Override AI provider (gemini, openai, claude, openrouter)"
    )
):
    """
    Quick port scan using Nmap
    
    Performs a basic port scan and service detection.
    For full workflow, use 'guardian workflow run'.
    """
    console.print(f"[bold cyan]🔍 Scanning: {target}[/bold cyan]\n")

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
        # Run nmap scan
        nmap = NmapTool(config)
        
        console.print(f"Running nmap scan on {target}...")
        results = asyncio.run(nmap.execute(target, ports=ports))
        
        # Display results
        parsed = results["parsed"]
        
        console.print(f"\n[bold green]✓ Scan completed![/bold green]\n")
        console.print(f"[bold]Open Ports:[/bold] {len(parsed['open_ports'])}")
        
        for service in parsed["services"]:
            console.print(f"  [cyan]{service['port']}[/cyan] - {service['service']} ({service['product']})")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

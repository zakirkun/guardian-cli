"""
Workflow orchestration engine
Coordinates agents and manages pentest execution flow
"""

import asyncio
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from core.agent import BaseAgent
from core.planner import PlannerAgent
from core.memory import PentestMemory, ToolExecution, Finding
from ai.gemini_client import GeminiClient
from utils.logger import get_logger
from utils.scope_validator import ScopeValidator


class WorkflowEngine:
    """Orchestrates the penetration testing workflow"""
    
    def __init__(self, config: Dict[str, Any], target: str):
        self.config = config
        self.target = target
        self.logger = get_logger(config)
        
        # Initialize components
        self.memory = PentestMemory(target)
        self.scope_validator = ScopeValidator(config)
        self.gemini_client = GeminiClient(config)
        
        # Initialize all agents
        from core.planner import PlannerAgent
        from core.tool_agent import ToolAgent
        from core.analyst_agent import AnalystAgent
        from core.reporter_agent import ReporterAgent
        
        self.planner = PlannerAgent(config, self.gemini_client, self.memory)
        self.tool_agent = ToolAgent(config, self.gemini_client, self.memory)
        self.analyst = AnalystAgent(config, self.gemini_client, self.memory)
        self.reporter = ReporterAgent(config, self.gemini_client, self.memory)
        
        # Workflow state
        self.is_running = False
        self.current_step = 0
        self.max_steps = config.get("workflows", {}).get("max_steps", 20)

        # Rich console for real-time display (set by CLI layer)
        self._console: Optional[Console] = None

    def set_console(self, console: Console):
        """Wire a Rich console for streaming output and AI panel display."""
        self._console = console
    
    async def run_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """
        Run a predefined workflow
        
        Args:
            workflow_name: Name of workflow (recon, web_pentest, network_pentest)
        
        Returns:
            Workflow results and findings
        """
        self.logger.info(f"Starting workflow: {workflow_name} for target: {self.target}")
        
        # Validate target
        is_valid, reason = self.scope_validator.validate_target(self.target)
        if not is_valid:
            self.logger.error(f"Target validation failed: {reason}")
            raise ValueError(f"Invalid target: {reason}")
        
        self.is_running = True
        self.memory.update_phase(f"{workflow_name}_workflow")
        
        try:
            # Load workflow steps
            steps = self._load_workflow(workflow_name)
            
            # Execute workflow steps
            for step in steps:
                if not self.is_running:
                    break
                
                self.logger.info(f"Executing step: {step['name']}")
                await self._execute_step(step)
                self.current_step += 1
            
            # Generate final analysis
            analysis = await self.planner.analyze_results()
            
            # Save final state
            self._save_session()
            
            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id
            }
            
        except Exception as e:
            self.logger.error(f"Workflow failed: {e}")
            self._save_session()
            raise
        finally:
            self.is_running = False
    
    async def run_autonomous(self) -> Dict[str, Any]:
        """
        Run autonomous pentest where AI decides each step
        
        Returns:
            Final results
        """
        self.logger.info(f"Starting autonomous pentest for target: {self.target}")
        
        # Validate target
        is_valid, reason = self.scope_validator.validate_target(self.target)
        if not is_valid:
            raise ValueError(f"Invalid target: {reason}")
        
        self.is_running = True
        self.memory.update_phase("reconnaissance")
        
        try:
            while self.is_running and self.current_step < self.max_steps:
                # Ask planner for next action
                decision = await self.planner.decide_next_action()
                
                self.logger.info(f"AI Decision: {decision.get('next_action')}")
                self.logger.debug(f"Reasoning: {decision.get('reasoning', 'N/A')}")
                
                # Check if we should stop
                if decision.get("next_action", "").lower() in ["done", "complete", "finish"]:
                    self.logger.info("Planner decided workflow is complete")
                    break
                
                # Execute the decided action
                await self._execute_ai_decision(decision)
                
                self.current_step += 1
                
                # Progress phase if needed
                self._maybe_advance_phase()
            
            # Final analysis
            analysis = await self.planner.analyze_results()
            
            self._save_session()
            
            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id
            }
            
        except Exception as e:
            self.logger.error(f"Autonomous workflow failed: {e}")
            self._save_session()
            raise
        finally:
            self.is_running = False
    
    def stop(self):
        """Stop the workflow"""
        self.logger.info("Stopping workflow")
        self.is_running = False
    
    async def _execute_step(self, step: Dict[str, Any]):
        """Execute a workflow step with streaming output and AI thinking display."""
        step_type = step.get("type", "tool")
        con = self._console  # may be None — all prints are guarded

        # ── TOOL step ────────────────────────────────────────────────────────
        if step_type == "tool":
            tool_name = step["tool"]
            objective  = step.get("objective", f"Execute {tool_name}")

            if con:
                con.print(Rule(f"[bold cyan]TOOL  {tool_name.upper()}[/bold cyan]", style="cyan"))
                con.print(f"  [dim]Objective:[/dim] {objective}")
                con.print(f"  [dim]Target   :[/dim] [yellow]{self.target}[/yellow]\n")

            self.logger.info(f"Tool Agent selecting tool: {tool_name}")

            # Build a line-by-line stream callback for Rich
            def _stream(line: str):
                if con and line.strip():
                    try:
                        con.print(line, markup=True, highlight=False)
                    except Exception:
                        con.print(line, markup=False)

            result = await self.tool_agent.execute_tool(
                tool_name=tool_name,
                target=self.target,          # always the exact CLI target
                stream_callback=_stream,
                **step.get("parameters", {}),
            )

            if result.get("skipped"):
                if con:
                    con.print(
                        Panel(
                            f"[yellow]Tool [bold]{tool_name}[/bold] is not installed — step skipped.[/yellow]\n"
                            f"Install it and re-run, or remove this step from the workflow.",
                            title="[yellow]SKIPPED[/yellow]",
                            border_style="yellow",
                        )
                    )
                self.logger.warning(f"Step '{step['name']}' skipped — tool {tool_name} not available")

            elif result.get("success"):
                # Record execution with unique ID
                import time
                execution_id = f"{tool_name}_{int(time.time() * 1000)}"

                execution = ToolExecution(
                    id=execution_id,
                    tool=tool_name,
                    command=result.get("command", ""),
                    target=self.target,
                    timestamp=datetime.now().isoformat(),
                    exit_code=result.get("exit_code", 0),
                    output=result.get("raw_output", ""),
                    duration=result.get("duration", 0),
                )
                self.memory.add_tool_execution(execution)

                # Analyst AI thinking panel
                self.logger.info("Analyst Agent analyzing results...")
                if con:
                    con.print(Rule("[bold green]AI ANALYST[/bold green]", style="green"))

                analysis = await self.analyst.interpret_output(
                    tool=tool_name,
                    target=self.target,
                    command=result.get("command", ""),
                    output=result.get("raw_output", ""),
                    execution_id=execution_id,
                )

                if con and analysis.get("reasoning"):
                    con.print(
                        Panel(
                            Text(analysis["reasoning"][:600], style="dim"),
                            title="[cyan]Analyst Reasoning[/cyan]",
                            border_style="cyan",
                            expand=False,
                        )
                    )

                self.logger.info(f"Found {len(analysis['findings'])} findings from {tool_name}")
                if con:
                    colour = "red" if analysis['findings'] else "green"
                    con.print(f"  [{colour}]Findings: {len(analysis['findings'])}[/{colour}]\n")

            else:
                err = result.get("error", "unknown error")
                self.logger.warning(f"Tool execution failed: {err}")
                if con:
                    con.print(f"  [red]Tool failed:[/red] {err}\n")

        # ── ANALYSIS step ────────────────────────────────────────────────────
        elif step_type == "analysis":
            if con:
                con.print(Rule("[bold magenta]AI CORRELATION ANALYSIS[/bold magenta]", style="magenta"))

            self.logger.info("Running correlation analysis...")
            analysis = await self.analyst.correlate_findings()
            self.logger.info("Correlation analysis complete")

            if con and analysis.get("analysis"):
                # Show a trimmed preview
                preview = analysis["analysis"][:800]
                con.print(
                    Panel(
                        Text(preview, style="white"),
                        title="[magenta]Correlation Result[/magenta]",
                        border_style="magenta",
                        expand=False,
                    )
                )

        # ── REPORT step ──────────────────────────────────────────────────────
        elif step_type == "report":
            config_format = self.config.get("output", {}).get("format", "markdown")
            report_format = step.get("format", config_format)

            if con:
                con.print(Rule(f"[bold blue]AI REPORTER — {report_format.upper()}[/bold blue]", style="blue"))

            self.logger.info(f"Generating {report_format} report...")
            report = await self.reporter.execute(format=report_format)

            output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
            output_dir.mkdir(parents=True, exist_ok=True)
            extension_map = {"markdown": "md", "html": "html", "json": "json"}
            extension = extension_map.get(report_format, "md")
            report_file = output_dir / f"report_{self.memory.session_id}.{extension}"

            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report["content"])

            self.logger.info(f"Report saved to: {report_file}")
            if con:
                con.print(f"  [green]Report saved:[/green] [link={report_file}]{report_file}[/link]\n")

        self.memory.mark_action_complete(step["name"])
    
    async def _execute_ai_decision(self, decision: Dict[str, Any]):
        """Execute an AI-decided action"""
        action = decision.get("next_action", "")
        
        self.logger.info(f"Executing AI decision: {action}")
        
        # Use Tool Agent to select appropriate tool
        try:
            tool_selection = await self.tool_agent.execute(
                objective=action,
                target=self.target
            )
            
            # Execute selected tool
            result = await self.tool_agent.execute_tool(
                tool_name=tool_selection["tool"],
                target=self.target
            )
            
            if result.get("success"):
                # Analyze with Analyst Agent
                analysis = await self.analyst.interpret_output(
                    tool=tool_selection["tool"],
                    target=self.target,
                    command=result.get("command", ""),
                    output=result.get("raw_output", "")
                )
                
                self.logger.info(f"Found {len(analysis['findings'])} new findings")
            
        except Exception as e:
            self.logger.error(f"Failed to execute AI decision: {e}")
        
        self.memory.mark_action_complete(action)
    
    def _load_workflow(self, workflow_name: str) -> List[Dict[str, Any]]:
        """Load workflow definition from YAML file"""
        import yaml
        
        # Determine project root and workflows directory
        project_root = Path(__file__).parent.parent
        workflows_dir = project_root / "workflows"
        
        self.logger.info(f"Looking for workflow: {workflow_name}")
        self.logger.info(f"Workflows directory: {workflows_dir}")
        
        # Try to find workflow file by name
        # Support both exact match and fuzzy match (e.g., "web" -> "web_pentest.yaml")
        workflow_file = None
        
        # Check for exact match first
        exact_file = workflows_dir / f"{workflow_name}.yaml"
        self.logger.debug(f"Checking exact match: {exact_file}")
        if exact_file.exists():
            workflow_file = exact_file
            self.logger.info(f"Found exact match: {workflow_file.name}")
        else:
            # Fuzzy search - find file that matches workflow_name
            # Check if file stem is IN workflow name OR workflow name is IN file stem
            self.logger.debug(f"Trying fuzzy match for: {workflow_name}")
            for yaml_file in workflows_dir.glob("*.yaml"):
                file_stem = yaml_file.stem.lower()
                workflow_lower = workflow_name.lower()
                
                self.logger.debug(f"  Checking: {yaml_file.stem}")
                
                # Match if file stem is in workflow name (e.g., web_pentest in web_application_pentest)
                # OR if workflow name is in file stem (e.g., web in web_pentest)
                if file_stem in workflow_lower or workflow_lower in file_stem:
                    workflow_file = yaml_file
                    self.logger.info(f"Found fuzzy match: {workflow_file.name} for {workflow_name}")
                    break
        
        if not workflow_file:
            self.logger.warning(f"Workflow file not found for: {workflow_name}")
            self.logger.warning("Using fallback workflow with basic steps")
            # Fallback to basic recon workflow
            return [
                {"name": "subdomain_discovery", "type": "tool", "tool": "subfinder"},
                {"name": "port_scanning", "type": "tool", "tool": "nmap"},
                {"name": "analysis", "type": "analysis"},
            ]
        
        # Load YAML workflow
        try:
            self.logger.info(f"Loading workflow file: {workflow_file}")
            with open(workflow_file, 'r', encoding='utf-8') as f:
                workflow_data = yaml.safe_load(f)
            
            self.logger.info(f"Successfully loaded workflow from: {workflow_file.name}")
            
            # Extract steps from YAML
            steps = workflow_data.get('steps', [])
            self.logger.info(f"Workflow has {len(steps)} steps")
            
            # Log each step for debugging
            for i, step in enumerate(steps):
                self.logger.debug(f"  Step {i+1}: {step.get('name')} (type: {step.get('type')})")
            
            # Store workflow settings for potential use
            self.workflow_settings = workflow_data.get('settings', {})
            
            return steps
            
        except Exception as e:
            self.logger.error(f"Failed to load workflow from {workflow_file}: {e}")
            self.logger.error(f"Exception details: {type(e).__name__}: {str(e)}")
            # Fallback to basic workflow
            return [
                {"name": "basic_scan", "type": "tool", "tool": "nmap"},
                {"name": "analysis", "type": "analysis"},
            ]

    
    def _maybe_advance_phase(self):
        """Advance to next phase based on progress"""
        phases = ["reconnaissance", "scanning", "analysis", "reporting"]
        current_idx = phases.index(self.memory.current_phase) if self.memory.current_phase in phases else 0
        
        # Simple heuristic: advance after certain number of steps
        if self.current_step % 5 == 0 and current_idx < len(phases) - 1:
            new_phase = phases[current_idx + 1]
            self.logger.info(f"Advancing to phase: {new_phase}")
            self.memory.update_phase(new_phase)
    
    def _save_session(self):
        """Save session state"""
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        state_file = output_dir / f"session_{self.memory.session_id}.json"
        self.memory.save_state(state_file)
        self.logger.info(f"Session saved to: {state_file}")

"""
Workflow orchestration engine
Coordinates agents and manages pentest execution flow
"""

import asyncio
from typing import Dict, Any, Optional, List, TYPE_CHECKING
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

if TYPE_CHECKING:
    from core.workflow_schema import WorkflowStep


class WorkflowEngine:
    """Orchestrates the penetration testing workflow"""
    
    def __init__(self, config: Dict[str, Any], target: str, assume_yes: bool = False):
        self.config = config
        self.target = target
        self.logger = get_logger(config)
        self.assume_yes = assume_yes
        
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
        Run a predefined workflow.

        Loads YAML, compiles to a DAG, executes generation-by-generation
        with up to ``max_parallel_tools`` concurrent steps per generation.
        Both v1 (linear) and v2 (DAG) YAML schemas accepted — v1 is migrated
        in-memory by the compiler so existing workflows keep working.

        Returns:
            Workflow results and findings
        """
        from core.workflow_schema import compile_workflow, WorkflowCompileError

        self.logger.info(f"Starting workflow: {workflow_name} for target: {self.target}")

        # Validate target
        is_valid, reason = self.scope_validator.validate_target(self.target)
        if not is_valid:
            self.logger.error(f"Target validation failed: {reason}")
            raise ValueError(f"Invalid target: {reason}")

        self.is_running = True
        self.memory.update_phase(f"{workflow_name}_workflow")

        try:
            doc = self._load_workflow_doc(workflow_name)
            try:
                compiled = compile_workflow(doc)
            except WorkflowCompileError as e:
                self.logger.error(f"Workflow compile failed: {e}")
                raise

            # Concurrency cap from config; honored per-generation.
            max_parallel = max(
                1,
                int(self.config.get("pentest", {}).get("max_parallel_tools", 3)),
            )
            sem = asyncio.Semaphore(max_parallel)
            self.logger.info(
                f"Workflow '{compiled.name}' has {len(compiled.steps)} steps "
                f"in {len(compiled.levels)} generations (max_parallel={max_parallel})"
            )

            # Per-step result store, used as the Jinja2 context for downstream
            # steps. Keyed by step.id.
            step_results: Dict[str, Dict[str, Any]] = {}

            for gen_idx, level in enumerate(compiled.levels):
                if not self.is_running:
                    break
                self.logger.info(
                    f"Generation {gen_idx + 1}/{len(compiled.levels)}: {level}"
                )

                async def _run_one(step_id: str) -> None:
                    step = compiled.steps[step_id]
                    if step_id in self.memory.completed_actions:
                        self.logger.info(
                            f"Skipping '{step_id}' — already completed (resumed)"
                        )
                        return
                    async with sem:
                        result = await self._execute_compiled_step(step, step_results)
                        step_results[step_id] = result
                        # Atomic checkpoint after each step.
                        self._save_session()

                await asyncio.gather(*[_run_one(sid) for sid in level])

            # Generate final analysis
            analysis = await self.planner.analyze_results()

            self._save_session()

            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id,
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
                # Atomic per-step checkpoint (item 10).
                self._save_session()
            
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

            # Confirmation gate (item 6: wire dead config). Active+ tools
            # require explicit user approval unless --yes was passed or
            # pentest.require_confirmation is false in config.
            if not self._confirm_tool(tool_name, step):
                if con:
                    con.print(
                        Panel(
                            f"[yellow]User declined to run [bold]{tool_name}[/bold] — step skipped.[/yellow]",
                            title="[yellow]SKIPPED[/yellow]",
                            border_style="yellow",
                        )
                    )
                self.logger.warning(f"Step '{step['name']}' skipped by user confirmation gate")
                self.memory.mark_action_complete(step["name"])
                return

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

                # Stash the full tool result so DSL v2 callers can pull
                # ``parsed``, ``success``, etc. into downstream Jinja context.
                self._last_step_result = result

                # Re-validate any newly discovered hosts before downstream steps
                # consume them. A recon tool returning a host that resolves into
                # a blacklisted range must not propagate to a follow-on scanner.
                self._validate_discovered_hosts(tool_name, result.get("parsed", {}))

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
            agent_kind = (step.get("agent") or "analyst").lower()

            # Three-role debate triage — run on every MEDIUM-fp finding.
            if agent_kind == "debate" or step.get("type_subtype") == "triage_debate":
                if con:
                    con.print(Rule("[bold magenta]TRIAGE DEBATE[/bold magenta]", style="magenta"))

                from core.agents.debate_triage import DebateTriage

                triage = DebateTriage(self.config, self.gemini_client, self.memory)
                ambiguous = [
                    f for f in self.memory.findings
                    if DebateTriage._extract_fp_probability(f) == "MEDIUM"
                ]
                self.logger.info(
                    f"Debate triage: {len(ambiguous)} ambiguous findings to debate"
                )

                for finding in ambiguous:
                    verdict = await triage.triage(finding)
                    self.logger.info(
                        f"Debate verdict for {finding.id}: {verdict.verdict} "
                        f"(severity → {verdict.adjusted_severity})"
                    )
                    # Apply judge's adjustments to the in-memory finding.
                    if verdict.verdict == "FALSE_POSITIVE":
                        finding.false_positive = True
                    finding.severity = verdict.adjusted_severity
                    if verdict.rationale:
                        finding.description = (
                            f"{finding.description}\n\n[Triage Verdict — "
                            f"{verdict.verdict}, conf={verdict.confidence}] "
                            f"{verdict.rationale}"
                        )

                if con:
                    fp_count = sum(1 for f in self.memory.findings if f.false_positive)
                    con.print(
                        f"  [green]Debate complete[/green]: "
                        f"{len(ambiguous)} debated, {fp_count} flagged as FP\n"
                    )
                return

            # Visual triage — vision-LLM enriches findings with screenshot evidence.
            if agent_kind == "visual" or step.get("type_subtype") == "visual_triage":
                if con:
                    con.print(Rule("[bold magenta]VISUAL TRIAGE[/bold magenta]", style="magenta"))

                from core.agents.visual_triage import VisualTriage

                visual = VisualTriage(self.config, self.gemini_client, self.memory)
                result = await visual.triage_findings()
                if result.get("skipped_reason"):
                    self.logger.info(f"Visual triage skipped: {result['skipped_reason']}")
                    if con:
                        con.print(f"  [yellow]Skipped:[/yellow] {result['skipped_reason']}\n")
                else:
                    n = len(result.get("enrichments", []))
                    self.logger.info(f"Visual triage enriched {n} findings")
                    if con:
                        con.print(f"  [green]Enriched[/green] {n} findings with image evidence\n")
                return

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
    
    def _confirm_tool(self, tool_name: str, step: Dict[str, Any]) -> bool:
        """Return True if the tool should run, False to skip.

        Honors ``pentest.require_confirmation`` from config and the ``--yes``
        CLI flag. Passive tools always proceed. Active/intrusive/destructive
        tools prompt unless the user has waived confirmation. In safe_mode,
        destructive tools are blocked even with --yes (they need an explicit
        config opt-out).
        """
        from core.tool_agent import TOOL_RISK_CLASS

        risk = TOOL_RISK_CLASS.get(tool_name, "active")
        require = self.config.get("pentest", {}).get("require_confirmation", True)
        safe_mode = self.config.get("pentest", {}).get("safe_mode", True)

        # Block destructive tools in safe_mode regardless of --yes.
        if risk == "destructive" and safe_mode:
            self.logger.warning(
                f"Tool {tool_name} is destructive and safe_mode is on — skipping. "
                "Set pentest.safe_mode=false in config to enable."
            )
            return False

        # Passive tools never prompt.
        if risk == "passive":
            return True

        # Confirmation disabled or pre-approved.
        if not require or self.assume_yes:
            return True

        # Interactive prompt.
        try:
            import typer
            params = step.get("parameters", {}) or {}
            param_str = ", ".join(f"{k}={v}" for k, v in params.items()) or "(defaults)"
            msg = (
                f"\n  Tool      : {tool_name} [risk: {risk}]\n"
                f"  Target    : {self.target}\n"
                f"  Parameters: {param_str}\n"
                f"  Run this tool?"
            )
            if self._console:
                self._console.print(msg)
            return typer.confirm("  Confirm", default=False)
        except Exception as e:
            # Non-interactive context (no TTY) — fall through to skip rather
            # than silently auto-approve.
            self.logger.warning(
                f"Could not prompt for confirmation ({e}); skipping {tool_name}. "
                "Pass --yes for unattended runs."
            )
            return False

    def _validate_discovered_hosts(self, tool_name: str, parsed: Dict[str, Any]):
        """Re-run scope validation for hosts a tool discovered.

        Recon tools (subfinder/amass/dnsrecon) and probers (httpx/nmap) emit
        hostnames or IPs in their parsed output. Without re-validation, a
        downstream step could scan an out-of-scope or blacklisted host that
        the initial single-target check never saw.

        Logs SCOPE_VIOLATION for each rejected host. Does not abort the
        workflow — abort is the responsibility of the consuming step that
        chooses to act on those hosts. Today nothing consumes parsed cross-step
        (DSL v1 has no var-passing), so this is a tripwire + audit log until
        DSL v2 lands; at that point variable interpolation will read from a
        filtered host list.
        """
        if not isinstance(parsed, dict):
            return

        candidate_keys = (
            "subdomains", "alive_hosts", "hosts", "live_hosts",
            "found_hosts", "results", "targets",
        )
        candidates: List[str] = []
        for key in candidate_keys:
            val = parsed.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        candidates.append(item)
                    elif isinstance(item, dict):
                        for h_key in ("host", "url", "ip", "address", "subdomain"):
                            h = item.get(h_key)
                            if isinstance(h, str):
                                candidates.append(h)
                                break

        rejected: List[str] = []
        for host in candidates:
            ok, reason = self.scope_validator.validate_target(host)
            if not ok:
                rejected.append(f"{host} ({reason})")

        if rejected:
            self.logger.warning(
                f"[{tool_name}] {len(rejected)} discovered host(s) failed scope re-validation: "
                + "; ".join(rejected[:5])
                + (f" (+{len(rejected) - 5} more)" if len(rejected) > 5 else "")
            )

    async def _execute_ai_decision(self, decision: Dict[str, Any]):
        """Execute an AI-decided action.

        This is the autonomous-loop counterpart to ``_execute_step``. It MUST
        keep the Finding ⇄ ToolExecution linkage that the workflow path
        provides, otherwise findings emitted from autonomous mode lose their
        evidence trail entirely.

        Three things this method gets right that the original did not:
          * Mints an ``execution_id`` and passes it to ``analyst.interpret_output``
            so findings carry the link.
          * Records the ``ToolExecution`` exactly once (the ToolAgent path
            already records on success — passing ``record_execution=False``
            would be cleaner, but the current ToolAgent contract records
            unconditionally on success, so we don't add a second record here).
          * Wraps any exception in a session save so a crash doesn't lose
            partial findings.
        """
        action = decision.get("next_action", "")
        self.logger.info(f"Executing AI decision: {action}")

        try:
            tool_selection = await self.tool_agent.execute(
                objective=action,
                target=self.target,
            )
            tool_name = tool_selection["tool"]

            # Confirmation gate also applies in autonomous mode.
            fake_step = {"name": action, "parameters": {}}
            if not self._confirm_tool(tool_name, fake_step):
                self.logger.warning(
                    f"Autonomous step '{action}' skipped by confirmation gate"
                )
                self.memory.mark_action_complete(action)
                return

            result = await self.tool_agent.execute_tool(
                tool_name=tool_name,
                target=self.target,
            )

            if result.get("success"):
                # Mint the execution_id the same way the workflow path does
                # so analyst-emitted Findings carry their evidence link.
                import time
                execution_id = f"{tool_name}_{int(time.time() * 1000)}"

                # Update the most-recent ToolExecution record (added by
                # ToolAgent.execute_tool) with the id so the link is consistent
                # with what we hand to the analyst. Avoids double-recording.
                if self.memory.tool_executions:
                    last = self.memory.tool_executions[-1]
                    if last.tool == tool_name and last.id is None:
                        last.id = execution_id

                # Re-validate any newly discovered hosts.
                self._validate_discovered_hosts(tool_name, result.get("parsed", {}))

                analysis = await self.analyst.interpret_output(
                    tool=tool_name,
                    target=self.target,
                    command=result.get("command", ""),
                    output=result.get("raw_output", ""),
                    execution_id=execution_id,
                )
                self.logger.info(
                    f"Found {len(analysis['findings'])} new findings (autonomous)"
                )

            # Honor planner-declared phase transition if present.
            phase_t = decision.get("phase_transition")
            if isinstance(phase_t, str) and phase_t in {
                "reconnaissance", "scanning", "analysis", "reporting"
            }:
                if phase_t != self.memory.current_phase:
                    self.logger.info(
                        f"Planner advancing phase: {self.memory.current_phase} → {phase_t}"
                    )
                    self.memory.update_phase(phase_t)

        except Exception as e:
            self.logger.error(f"Failed to execute AI decision: {e}")
            # Persist whatever findings we have so a crash mid-loop doesn't
            # lose evidence collected before the failure.
            self._save_session()

        self.memory.mark_action_complete(action)
    
    def _load_workflow_doc(self, workflow_name: str) -> Dict[str, Any]:
        """Load workflow YAML as a dict (compiler-ready). DSL v2 entry point."""
        import yaml

        project_root = Path(__file__).parent.parent
        workflows_dir = project_root / "workflows"

        # Exact match → fuzzy substring match on stems.
        workflow_file: Optional[Path] = workflows_dir / f"{workflow_name}.yaml"
        if not workflow_file.exists():
            workflow_file = None
            for yaml_file in workflows_dir.glob("*.yaml"):
                stem = yaml_file.stem.lower()
                wn = workflow_name.lower()
                if stem in wn or wn in stem:
                    workflow_file = yaml_file
                    break

        if workflow_file is None:
            self.logger.warning(
                f"Workflow file not found for '{workflow_name}' — using fallback"
            )
            return {
                "version": 2,
                "name": "fallback",
                "steps": [
                    {"id": "subdomain_discovery", "type": "tool", "tool": "subfinder"},
                    {"id": "port_scanning", "type": "tool", "tool": "nmap",
                     "depends_on": ["subdomain_discovery"]},
                    {"id": "analysis", "type": "analysis",
                     "depends_on": ["port_scanning"]},
                ],
            }

        self.logger.info(f"Loading workflow: {workflow_file.name}")
        with open(workflow_file, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        return doc

    async def _execute_compiled_step(
        self,
        step: "WorkflowStep",  # type: ignore[name-defined]
        prior: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Execute one compiled step, returning a result dict for Jinja context.

        The returned dict shape mirrors a tool result so downstream ``when``
        expressions and ``parameters`` can reference ``<id>.parsed.<key>``,
        ``<id>.success``, etc.
        """
        from core.workflow_schema import (
            WorkflowCompileError,
            evaluate_when,
            render_parameters,
        )

        # Evaluate ``when`` against prior results.
        try:
            should_run = evaluate_when(step.when, prior)
        except WorkflowCompileError as e:
            self.logger.error(f"Step '{step.id}' when-expr failed: {e}")
            return {"success": False, "skipped": True, "error": str(e)}

        if not should_run:
            self.logger.info(f"Step '{step.id}' skipped — when-expr evaluated false")
            self.memory.mark_action_complete(step.id)
            return {"success": False, "skipped": True, "reason": "when-false"}

        # Render parameters with prior results in scope.
        try:
            rendered_params = render_parameters(dict(step.parameters or {}), prior)
        except WorkflowCompileError as e:
            self.logger.error(f"Step '{step.id}' parameter render failed: {e}")
            return {"success": False, "skipped": True, "error": str(e)}

        # Bridge to the existing v1 step executor by building a v1-shaped dict.
        v1_step: Dict[str, Any] = {
            "name": step.id,
            "type": step.type,
            "objective": step.objective,
            "parameters": rendered_params,
        }
        if step.tool:
            v1_step["tool"] = step.tool
        if step.agent:
            v1_step["agent"] = step.agent

        # _execute_step records its own result via memory side-effects.
        # Capture the cached tool result for DSL v2 prior-step references.
        self._last_step_result = None
        before = len(self.memory.tool_executions)
        await self._execute_step(v1_step)
        after = len(self.memory.tool_executions)

        last_exec = (
            self.memory.tool_executions[-1]
            if after > before
            else None
        )
        cached = getattr(self, "_last_step_result", None) or {}
        return {
            "id": step.id,
            "success": last_exec is not None and last_exec.exit_code == 0,
            "command": last_exec.command if last_exec else "",
            "exit_code": last_exec.exit_code if last_exec else -1,
            "parsed": cached.get("parsed", {}) if isinstance(cached, dict) else {},
            "raw_output": (last_exec.output if last_exec else "")[:8000],
        }

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
        """Phase transitions are now planner-driven (set via ``phase_transition``
        on the planner's ``PlannerDecision``). This method is kept as a no-op
        for autonomous-loop callers that haven't been migrated; the previous
        ``current_step % 5`` heuristic was fired regardless of progress and
        produced misleading "phase: reporting" labels mid-recon.
        """
        return
    
    def _save_session(self):
        """Save session state atomically.

        Uses temp-file + os.replace so a crash mid-write cannot leave a
        truncated session.json that breaks ``--resume``. PentestMemory's
        save_state already does the open/write/close cleanly, but it writes
        directly to the target path; we trampoline through a sibling temp
        file to make replacement atomic on POSIX and best-effort atomic on
        Windows.
        """
        import os
        import tempfile

        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)

        final = output_dir / f"session_{self.memory.session_id}.json"
        # NamedTemporaryFile in same dir so os.replace stays on one filesystem.
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=output_dir,
            prefix=f".session_{self.memory.session_id}_",
            suffix=".tmp",
            encoding="utf-8",
        ) as tmp:
            tmp_path = Path(tmp.name)
        try:
            self.memory.save_state(tmp_path)
            os.replace(tmp_path, final)
            self.logger.debug(f"Checkpoint saved: {final}")
        except Exception:
            # Cleanup partial temp on failure; do not mask the original error.
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    def resume_session(self, session_id: str) -> bool:
        """Load a prior session checkpoint into memory.

        Returns True on success, False if the session file is missing or
        unreadable. Used by the ``--resume`` flag on ``workflow run``.
        """
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        state_file = output_dir / f"session_{session_id}.json"
        if not state_file.exists():
            self.logger.error(f"Cannot resume: session file not found: {state_file}")
            return False
        ok = self.memory.load_state(state_file)
        if ok:
            self.target = self.memory.target
            self.current_step = len(self.memory.completed_actions)
            self.logger.info(
                f"Resumed session {session_id} at phase '{self.memory.current_phase}' "
                f"with {len(self.memory.findings)} findings, "
                f"{self.current_step} steps already completed"
            )
        return ok

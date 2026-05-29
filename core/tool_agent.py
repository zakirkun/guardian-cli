"""
Tool Selector Agent
Selects appropriate pentesting tools and configures them
"""

from typing import Dict, Any, Optional, Type
from core.agent import BaseAgent
from ai.prompt_templates import (
    TOOL_SELECTOR_SYSTEM_PROMPT,
    TOOL_SELECTION_PROMPT,
    TOOL_PARAMETERS_PROMPT
)


# ── Tool registry ────────────────────────────────────────────────────────────
# Maps tool name -> "module:Class" path. Resolved on first use only, so
# `guardian --help` and `workflow list` no longer pay the cost of importing
# all 20 wrappers (each calling shutil.which) at startup.
TOOL_REGISTRY: Dict[str, str] = {
    "nmap":      "tools.nmap:NmapTool",
    "httpx":     "tools.httpx:HttpxTool",
    "subfinder": "tools.subfinder:SubfinderTool",
    "nuclei":    "tools.nuclei:NucleiTool",
    "whatweb":   "tools.whatweb:WhatWebTool",
    "wafw00f":   "tools.wafw00f:Wafw00fTool",
    "nikto":     "tools.nikto:NiktoTool",
    "testssl":   "tools.testssl:TestSSLTool",
    "gobuster":  "tools.gobuster:GobusterTool",
    "sqlmap":    "tools.sqlmap:SQLMapTool",
    "ffuf":      "tools.ffuf:FFufTool",
    "amass":     "tools.amass:AmassTool",
    "wpscan":    "tools.wpscan:WPScanTool",
    "sslyze":    "tools.sslyze:SSLyzeTool",
    "masscan":   "tools.masscan:MasscanTool",
    "arjun":     "tools.arjun:ArjunTool",
    "xsstrike":  "tools.xsstrike:XSStrikeTool",
    "gitleaks":  "tools.gitleaks:GitleaksTool",
    "cmseek":    "tools.cmseek:CMSeekTool",
    "dnsrecon":  "tools.dnsrecon:DnsReconTool",
    # Phase 3 — cloud / container / SBOM
    "trivy":      "tools.trivy:TrivyTool",
    "grype":      "tools.grype:GrypeTool",
    "syft":       "tools.syft:SyftTool",
    "scoutsuite": "tools.scoutsuite:ScoutSuiteTool",
    "prowler":    "tools.prowler:ProwlerTool",
    "kube-bench": "tools.kube_bench:KubeBenchTool",
    # Phase 3 — modern web + OSINT
    "graphw00f":    "tools.graphw00f:Graphw00fTool",
    "clairvoyance": "tools.clairvoyance:ClairvoyanceTool",
    "jwt_tool":     "tools.jwt_tool:JwtTool",
    "shodan":       "tools.shodan:ShodanTool",
    "theharvester": "tools.theharvester:TheHarvesterTool",
    # Phase 4 — SAST + secrets (B11)
    "semgrep":          "tools.semgrep:SemgrepTool",
    "trufflehog":       "tools.trufflehog:TruffleHogTool",
    "dependency-check": "tools.dependency_check:DependencyCheckTool",
    # Phase 4 — API fuzzers (B10)
    "schemathesis": "tools.schemathesis:SchemathesisTool",
    "cariddi":      "tools.cariddi:CariddiTool",
    "restler":      "tools.restler:RestlerTool",
    # Phase 4 — Burp/ZAP automation (B13). Daemon runs out-of-band.
    "zap":  "tools.zap_api:ZapApiTool",
    "burp": "tools.burp_api:BurpApiTool",
    # Phase 4 — LLM red-team (B12).
    "garak":       "tools.garak:GarakTool",
    "pyrit":       "tools.pyrit:PyritTool",
    "prompt_fuzz": "tools.prompt_fuzz:PromptFuzzTool",
    # Phase 4 — Mobile Android (B9).
    "mobsf":     "tools.mobsf:MobSFTool",
    "apkleaks":  "tools.apkleaks:ApkLeaksTool",
    "objection": "tools.objection_runtime:ObjectionRuntimeTool",
    # Phase 4 — Active Directory (B8). Authorized AD engagements only.
    "crackmapexec":          "tools.crackmapexec:CrackMapExecTool",
    "bloodhound":            "tools.bloodhound:BloodHoundTool",
    "kerbrute":              "tools.kerbrute:KerbruteTool",
    "impacket-secretsdump":  "tools.impacket_secretsdump:ImpacketSecretsdumpTool",
    # Phase 4 — Vision evidence (A3). Headless screenshotter for visual triage.
    "playwright_screenshot": "tools.playwright_screenshot:PlaywrightScreenshotTool",
}


# Risk classification per tool (drives the confirmation gate in
# core/workflow.py when pentest.require_confirmation is true).
#   passive    – read-only / passive-DNS / no traffic to target
#   active     – sends benign probes (banner grabs, HEAD requests)
#   intrusive  – injects payloads or fuzzes (may trigger WAF, file writes)
#   destructive – may modify state (sqlmap stacked queries, brute force)
TOOL_RISK_CLASS: Dict[str, str] = {
    # Passive recon
    "subfinder":  "passive",
    "amass":      "passive",
    "dnsrecon":   "passive",
    "gitleaks":   "passive",
    # Active probes
    "httpx":      "active",
    "whatweb":    "active",
    "wafw00f":    "active",
    "cmseek":     "active",
    "nmap":       "active",
    "masscan":    "active",
    "testssl":    "active",
    "sslyze":     "active",
    # Intrusive scanners / fuzzers
    "nuclei":     "intrusive",
    "nikto":      "intrusive",
    "wpscan":     "intrusive",
    "gobuster":   "intrusive",
    "ffuf":       "intrusive",
    "arjun":      "intrusive",
    "xsstrike":   "intrusive",
    # Destructive
    "sqlmap":     "destructive",
    # Phase 3 additions
    "trivy":        "passive",   # offline CVE / IaC scan
    "grype":        "passive",
    "syft":         "passive",
    "scoutsuite":   "passive",   # read-only cloud API
    "prowler":      "passive",
    "kube-bench":   "passive",
    "shodan":       "passive",   # external API only
    "theharvester": "passive",
    "graphw00f":    "active",    # introspection probes
    "jwt_tool":     "intrusive", # forges + replays tokens
    "clairvoyance": "intrusive", # heavy fuzzing
    # Phase 4 SAST tier — read-only.
    "semgrep":          "passive",
    "trufflehog":       "passive",
    "dependency-check": "passive",
    # Phase 4 API fuzzers — generate real traffic.
    "schemathesis": "intrusive",
    "cariddi":      "active",
    "restler":      "intrusive",
    # Phase 4 Burp/ZAP — daemons run intrusive scans.
    "zap":  "intrusive",
    "burp": "intrusive",
    # Phase 4 LLM red-team (B12) — sends adversarial prompts.
    "garak":       "intrusive",
    "pyrit":       "intrusive",
    "prompt_fuzz": "intrusive",
    # Phase 4 Mobile (B9). Static = passive; runtime modifies process memory.
    "mobsf":     "passive",
    "apkleaks":  "passive",
    "objection": "intrusive",
    # Phase 4 AD toolkit (B8). All authenticated engagement work.
    # ``impacket-secretsdump`` runs DCSync — destructive (event-logged).
    # Spray + cred validation = intrusive. Enum-only is also intrusive
    # because it generates auth events.
    "crackmapexec":         "intrusive",
    "bloodhound":           "intrusive",
    "kerbrute":             "intrusive",
    "impacket-secretsdump": "destructive",
    # Phase 4 — Vision (A3). Same blast radius as a normal HTTP GET + render.
    "playwright_screenshot": "active",
}


def _import_tool(spec: str) -> Type:
    """Import a 'module:Class' specifier and return the class."""
    import importlib
    module_path, class_name = spec.split(":")
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


# Cache for entry-point-discovered tools. Computed once per process.
_TOOL_REGISTRY_CACHE: Optional[Dict[str, str]] = None


def _discover_plugin_tools() -> Dict[str, str]:
    """Merge entry-point-declared tool wrappers with the in-tree registry.

    Plugin packages register via:

        [project.entry-points."guardian.tools"]
        my_scanner = "my_pkg.my_scanner:MyScannerTool"

    In-tree wins on name collisions — plugins cannot silently override
    a core tool. Risk classification falls back to ``"active"`` for
    plugin-declared tools that don't extend ``TOOL_RISK_CLASS`` themselves.
    """
    global _TOOL_REGISTRY_CACHE
    if _TOOL_REGISTRY_CACHE is not None:
        return _TOOL_REGISTRY_CACHE

    merged = dict(TOOL_REGISTRY)
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover
        _TOOL_REGISTRY_CACHE = merged
        return merged

    try:
        eps = entry_points(group="guardian.tools")
    except TypeError:
        eps = entry_points().get("guardian.tools", [])  # type: ignore[union-attr]

    for ep in eps:
        if ep.name in TOOL_REGISTRY:
            continue  # in-tree wins
        merged[ep.name] = ep.value
        # Default risk class for plugins that don't extend TOOL_RISK_CLASS.
        TOOL_RISK_CLASS.setdefault(ep.name, "active")

    _TOOL_REGISTRY_CACHE = merged
    return merged


class ToolAgent(BaseAgent):
    """Agent that selects and configures pentesting tools"""

    def __init__(self, config, gemini_client, memory):
        super().__init__("ToolSelector", config, gemini_client, memory)
        self._instances: Dict[str, Any] = {}  # lazy-instantiated tool cache
        # Optional offline ranker — lazy-load on first execute() call so
        # CLI startup stays fast.
        self._ranker = None
        self._ranker_attempted = False

    def _get_tool(self, tool_name: str):
        """Resolve and cache a tool instance on first use."""
        if tool_name in self._instances:
            return self._instances[tool_name]
        registry = _discover_plugin_tools()
        spec = registry.get(tool_name)
        if spec is None:
            return None
        cls = _import_tool(spec)
        instance = cls(self.config)
        self._instances[tool_name] = instance
        return instance

    @property
    def available_tools(self) -> Dict[str, Any]:
        """Backwards-compat shim: returns the cache so far. Most callers
        only need `.keys()`, which we satisfy via TOOL_REGISTRY directly.
        Prefer `_get_tool()` or `get_available_tools()` for new code.
        """
        return self._instances
    async def execute(self, objective: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Select and configure the best tool for an objective

        Args:
            objective: What we're trying to accomplish
            target: Target to scan
            **kwargs: Additional context

        Returns:
            Dict with selected tool and configuration
        """
        # Determine target type
        target_type = self._detect_target_type(target)

        # Offline ranker — fast pre-filter, abstains when low-confidence.
        ranked_tool = self._predict_with_ranker(target_type)
        if ranked_tool is not None:
            self.log_action("ToolSelected", f"{ranked_tool} for {objective} (ranker)")
            return {
                "tool": ranked_tool,
                "arguments": "",
                "reasoning": f"Offline ranker confident pick (target_type={target_type}, phase={self.memory.current_phase})",
                "expected_output": "",
            }

        # Get context from memory
        context = self.memory.get_context_for_ai()
        
        # Gather constraint config
        safe_mode   = self.config.get("pentest", {}).get("safe_mode", True)
        rate_limit  = self.config.get("ai", {}).get("rate_limit", 60)
        timeout     = self.config.get("pentest", {}).get("tool_timeout", 300)
        stealth     = kwargs.get("stealth", False)

        # Build installed-tools list from the registry (incl. plugins).
        installed_tools_str = ", ".join(sorted(_discover_plugin_tools().keys()))

        # Summarise prior tool outputs (tool names already run)
        prior_tools_run = ", ".join(
            t.tool for t in self.memory.tool_executions
        ) or "None yet"

        # Ask AI to select tool
        prompt = TOOL_SELECTION_PROMPT.format(
            objective=objective,
            target=target,
            target_type=target_type,
            phase=self.memory.current_phase,
            context=context,
            installed_tools=installed_tools_str,
            prior_tool_outputs=prior_tools_run,
            safe_mode=safe_mode,
            stealth=stealth,
            rate_limit=rate_limit,
            timeout=timeout,
        )
        
        result = await self.think(prompt, TOOL_SELECTOR_SYSTEM_PROMPT)
        
        # Parse tool selection
        tool_selection = self._parse_selection(result["response"])
        
        self.log_action("ToolSelected", f"{tool_selection['tool']} for {objective}")
        
        return {
            "tool": tool_selection["tool"],
            "arguments": tool_selection.get("arguments", ""),
            "reasoning": result["reasoning"],
            "expected_output": tool_selection.get("expected_output", "")
        }
    
    async def configure_tool(self, tool_name: str, objective: str, target: str) -> Dict[str, Any]:
        """
        Generate optimal parameters for a specific tool
        
        Returns:
            Dict with tool parameters and justification
        """
        safe_mode = self.config.get("pentest", {}).get("safe_mode", True)
        timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        
        target_type = self._detect_target_type(target)
        rate_limit  = self.config.get("ai", {}).get("rate_limit", 60)
        context     = self.memory.get_context_for_ai()

        prompt = TOOL_PARAMETERS_PROMPT.format(
            tool=tool_name,
            objective=objective,
            target=target,
            target_type=target_type,
            context=context,
            safe_mode=safe_mode,
            stealth=False,
            timeout=timeout,
            rate_limit=rate_limit,
        )
        
        result = await self.think(prompt, TOOL_SELECTOR_SYSTEM_PROMPT)
        
        return {
            "parameters": result["response"],
            "justification": result["reasoning"]
        }
    
    async def execute_tool(
        self,
        tool_name: str,
        target: str,
        stream_callback=None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute a selected tool against `target`.

        Args:
            tool_name:       Name of the registered tool.
            target:          Exact target as supplied by the user.
            stream_callback: Optional callable(line: str) for real-time output.

        Returns:
            Result dict with 'success', 'raw_output', etc.
            Never raises — returns success=False on any failure.
        """
        if tool_name not in _discover_plugin_tools():
            self.logger.warning(f"Unknown tool requested: {tool_name} — skipping")
            return {"success": False, "skipped": True, "tool": tool_name,
                    "error": f"Tool '{tool_name}' not registered", "raw_output": ""}

        tool = self._get_tool(tool_name)

        # is_available is checked inside base_tool.execute() and returns a
        # skipped result — but we also short-circuit here for speed.
        if not tool.is_available:
            self.logger.warning(f"Tool {tool_name} is not installed — skipping")
            return {"success": False, "skipped": True, "tool": tool_name,
                    "error": f"Tool '{tool_name}' not installed", "raw_output": ""}

        try:
            result = await tool.execute(target, stream_callback=stream_callback, **kwargs)

            if result.get("success"):
                # Record successful execution in memory
                from core.memory import ToolExecution
                execution = ToolExecution(
                    tool=tool_name,
                    command=result.get("command", ""),
                    target=target,
                    timestamp=result.get("timestamp", ""),
                    exit_code=result.get("exit_code", 0),
                    output=result.get("raw_output", ""),
                    duration=result.get("duration", 0.0),
                )
                self.memory.add_tool_execution(execution)

            return {
                "success":    result.get("success", False),
                "skipped":    result.get("skipped", False),
                "tool":       tool_name,
                "command":    result.get("command", ""),
                "parsed":     result.get("parsed", {}),
                "raw_output": result.get("raw_output", ""),
                "duration":   result.get("duration", 0.0),
                "exit_code":  result.get("exit_code", -1),
                "error":      result.get("error"),
            }

        except Exception as e:
            self.logger.error(f"Unexpected error in execute_tool({tool_name}): {e}")
            return {"success": False, "skipped": False, "tool": tool_name,
                    "error": str(e), "raw_output": ""}

    
    def _detect_target_type(self, target: str) -> str:
        """Detect if target is IP, domain, or URL"""
        from utils.helpers import is_valid_ip, is_valid_domain, is_valid_url
        
        if is_valid_url(target):
            return "url"
        elif is_valid_ip(target):
            return "ip"
        elif is_valid_domain(target):
            return "domain"
        else:
            return "unknown"
    
    def _parse_selection(self, response: str) -> Dict[str, str]:
        """Parse AI tool selection response"""
        selection = {
            "tool": "nmap",  # Default
            "arguments": "",
            "expected_output": ""
        }
        
        # Simple parsing
        if "TOOL:" in response:
            start = response.find("TOOL:") + len("TOOL:")
            end = response.find("ARGUMENTS:", start) if "ARGUMENTS:" in response else len(response)
            selection["tool"] = response[start:end].strip().lower()
        
        if "ARGUMENTS:" in response:
            start = response.find("ARGUMENTS:") + len("ARGUMENTS:")
            end = response.find("EXPECTED_OUTPUT:", start) if "EXPECTED_OUTPUT:" in response else len(response)
            selection["arguments"] = response[start:end].strip()
        
        if "EXPECTED_OUTPUT:" in response:
            start = response.find("EXPECTED_OUTPUT:") + len("EXPECTED_OUTPUT:")
            selection["expected_output"] = response[start:].strip()
        
        return selection
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get installation status of every registered tool.

        Triggers lazy instantiation for tools not yet seen — that is the cost
        of answering this query. Cached afterwards.
        """
        return {
            name: self._get_tool(name).is_available
            for name in _discover_plugin_tools()
        }

    # ── Offline ranker integration (A5) ──────────────────────────────────────

    def _predict_with_ranker(self, target_type: str) -> Optional[str]:
        """Try the offline ranker. Return ``None`` if disabled, untrained,
        or low-confidence — caller falls back to LLM selection.

        The ranker is loaded once per ToolAgent. Failures are silent — a
        missing model is the default state, not an error.
        """
        if not self.config.get("ai", {}).get("use_learned_ranker", False):
            return None

        if not self._ranker_attempted:
            self._ranker_attempted = True
            try:
                from core.learners.tool_ranker import ToolRanker
                self._ranker = ToolRanker.load()
            except Exception as e:
                self.logger.debug(f"Ranker load skipped: {e}")
                self._ranker = None

        if self._ranker is None:
            return None

        from core.learners.tool_ranker import RankerFeatures
        feats = RankerFeatures(
            target_type=target_type,
            phase=self.memory.current_phase or "unknown",
            prior_tool_count=len(self.memory.tool_executions),
            prior_findings_count=len(self.memory.findings),
        )
        try:
            tool = self._ranker.predict_with_fallback(feats)
        except Exception as e:
            self.logger.debug(f"Ranker predict skipped: {e}")
            return None

        if tool is None:
            return None
        # Reject ranker picks for unregistered tools — corpus drift can
        # surface tools that were renamed or removed.
        if tool not in _discover_plugin_tools():
            self.logger.debug(f"Ranker chose unknown tool '{tool}', falling back")
            return None
        return tool

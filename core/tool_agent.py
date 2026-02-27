"""
Tool Selector Agent
Selects appropriate pentesting tools and configures them
"""

from typing import Dict, Any, Optional
from core.agent import BaseAgent
from ai.prompt_templates import (
    TOOL_SELECTOR_SYSTEM_PROMPT,
    TOOL_SELECTION_PROMPT,
    TOOL_PARAMETERS_PROMPT
)
from tools import NmapTool, HttpxTool, SubfinderTool, NucleiTool


class ToolAgent(BaseAgent):
    """Agent that selects and configures pentesting tools"""
    
    def __init__(self, config, gemini_client, memory):
        super().__init__("ToolSelector", config, gemini_client, memory)
        
        # Initialize available tools
        from tools import (
            NmapTool, HttpxTool, SubfinderTool, NucleiTool,
            WhatWebTool, Wafw00fTool, NiktoTool, TestSSLTool, GobusterTool,
            SQLMapTool, FFufTool, AmassTool, WPScanTool, SSLyzeTool, MasscanTool,
            ArjunTool, XSStrikeTool, GitleaksTool, CMSeekTool, DnsReconTool
        )
        
        self.available_tools = {
            "nmap": NmapTool(config),
            "httpx": HttpxTool(config),
            "subfinder": SubfinderTool(config),
            "nuclei": NucleiTool(config),
            "whatweb": WhatWebTool(config),
            "wafw00f": Wafw00fTool(config),
            "nikto": NiktoTool(config),
            "testssl": TestSSLTool(config),
            "gobuster": GobusterTool(config),
            "sqlmap": SQLMapTool(config),
            "ffuf": FFufTool(config),
            "amass": AmassTool(config),
            "wpscan": WPScanTool(config),
            "sslyze": SSLyzeTool(config),
            "masscan": MasscanTool(config),
            "arjun": ArjunTool(config),
            "xsstrike": XSStrikeTool(config),
            "gitleaks": GitleaksTool(config),
            "cmseek": CMSeekTool(config),
            "dnsrecon": DnsReconTool(config),
        }

    
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
        
        # Get context from memory
        context = self.memory.get_context_for_ai()
        
        # Gather constraint config
        safe_mode   = self.config.get("pentest", {}).get("safe_mode", True)
        rate_limit  = self.config.get("ai", {}).get("rate_limit", 60)
        timeout     = self.config.get("pentest", {}).get("tool_timeout", 300)
        stealth     = kwargs.get("stealth", False)

        # Build installed-tools list from what's registered
        installed_tools_str = ", ".join(sorted(self.available_tools.keys()))

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
        if tool_name not in self.available_tools:
            self.logger.warning(f"Unknown tool requested: {tool_name} — skipping")
            return {"success": False, "skipped": True, "tool": tool_name,
                    "error": f"Tool '{tool_name}' not registered", "raw_output": ""}

        tool = self.available_tools[tool_name]

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
        """Get status of all tools"""
        return {
            name: tool.is_available
            for name, tool in self.available_tools.items()
        }

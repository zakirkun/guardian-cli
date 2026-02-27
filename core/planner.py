"""
Strategic Planner Agent
Decides next steps in the penetration testing workflow
"""

from typing import Dict, Any
from core.agent import BaseAgent
from ai.prompt_templates import (
    PLANNER_SYSTEM_PROMPT,
    PLANNER_DECISION_PROMPT,
    PLANNER_ANALYSIS_PROMPT
)


class PlannerAgent(BaseAgent):
    """Strategic planner that decides next pentest steps"""
    
    def __init__(self, config, gemini_client, memory):
        super().__init__("Planner", config, gemini_client, memory)
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Decide the next action in the penetration test"""
        return await self.decide_next_action()
    
    async def decide_next_action(self) -> Dict[str, Any]:
        """
        Analyze current state and decide next action
        
        Returns:
            Dict with next_action, parameters, reasoning
        """
        # Build context
        context = self.memory.get_context_for_ai()
        findings_summary = self._format_findings()
        available_actions = self._get_available_actions()
        
        prompt = PLANNER_DECISION_PROMPT.format(
            phase=self.memory.current_phase,
            target=self.memory.target,
            session_id=self.memory.session_id,
            completed_actions="\n".join(f"- {a}" for a in self.memory.completed_actions) or "None",
            findings=findings_summary,
            attack_surface="\n".join(f"- {e}" for e in self.memory.attack_surface) or "None discovered",
            technologies=", ".join(self.memory.context.get("technologies", [])) or "Unknown",
            threat_model=self.memory.threat_model[:600] if self.memory.threat_model else "Not yet built",
            prior_reasoning_chain=self.memory.get_recent_thinking(3),
            available_actions=available_actions,
        )
        
        # Get AI decision
        result = await self.think(prompt, PLANNER_SYSTEM_PROMPT)
        
        # Parse the response
        decision = self._parse_decision(result["response"])
        decision["reasoning"] = result["reasoning"]
        
        self.log_action("Decision", decision.get("next_action", "Unknown"))
        
        return decision
    
    async def analyze_results(self) -> Dict[str, str]:
        """Provide strategic analysis of pentest results"""
        findings_summary = self._format_findings()
        tools_executed = "\n".join(
            f"- {t.tool} on {t.target}" for t in self.memory.tool_executions
        )
        
        prompt = PLANNER_ANALYSIS_PROMPT.format(
            target=self.memory.target,
            phase=self.memory.current_phase,
            findings_summary=findings_summary,
            tools_executed=tools_executed or "None",
            decision_count=len(self.memory.ai_decisions),
            thinking_steps=len(self.memory.thinking_chain),
        )
        
        result = await self.think(prompt, PLANNER_SYSTEM_PROMPT)
        
        return result
    
    def _format_findings(self) -> str:
        """Format findings for AI consumption"""
        if not self.memory.findings:
            return "No findings yet"
        
        findings_by_severity = {}
        for finding in self.memory.findings:
            if not finding.false_positive:
                severity = finding.severity.lower()
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding.title)
        
        formatted = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in findings_by_severity:
                formatted.append(f"\n{severity.upper()}:")
                for title in findings_by_severity[severity]:
                    formatted.append(f"  - {title}")
        
        return "\n".join(formatted)
    
    def _get_available_actions(self) -> str:
        """Get list of available actions based on current phase"""
        all_actions = {
            "reconnaissance": [
                "subdomain_enumeration - Discover subdomains",
                "dns_enumeration - Gather DNS records",
                "technology_detection - Identify web technologies",
                "port_scanning - Scan for open ports"
            ],
            "scanning": [
                "service_detection - Identify services on open ports",
                "vulnerability_scanning - Run vulnerability scanners",
                "web_probing - Probe web services",
                "ssl_analysis - Analyze SSL/TLS configuration"
            ],
            "analysis": [
                "correlate_findings - Combine data from multiple tools",
                "risk_assessment - Analyze security posture",
                "false_positive_filter - Filter out false positives",
                "prioritize_vulns - Rank vulnerabilities by risk"
            ],
            "reporting": [
                "generate_report - Create final report",
                "executive_summary - Write executive summary",
                "remediation_plan - Create fix recommendations"
            ]
        }
        
        phase = self.memory.current_phase
        actions = all_actions.get(phase, all_actions["reconnaissance"])
        
        return "\n".join(f"- {action}" for action in actions)
    
    def _parse_decision(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured decision"""
        decision = {
            "next_action": "unknown",
            "parameters": {},
            "expected_outcome": ""
        }
        
        # Simple parsing of the AI response
        if "NEXT_ACTION:" in response:
            start = response.find("NEXT_ACTION:") + len("NEXT_ACTION:")
            end = response.find("PARAMETERS:", start) if "PARAMETERS:" in response else len(response)
            decision["next_action"] = response[start:end].strip()
        
        if "PARAMETERS:" in response:
            start = response.find("PARAMETERS:") + len("PARAMETERS:")
            end = response.find("EXPECTED_OUTCOME:", start) if "EXPECTED_OUTCOME:" in response else len(response)
            decision["parameters"] = response[start:end].strip()
        
        if "EXPECTED_OUTCOME:" in response:
            start = response.find("EXPECTED_OUTCOME:") + len("EXPECTED_OUTCOME:")
            decision["expected_outcome"] = response[start:].strip()
        
        return decision

"""
Strategic Planner Agent
Decides next steps in the penetration testing workflow
"""

import json
import re
from typing import Dict, Any
from core.agent import BaseAgent
from core.schemas import PlannerDecision, parse_or_none
from utils.sanitize import strip_control_chars, wrap_untrusted
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
            # Findings/attack_surface/technologies are derived from external tool
            # output and must be treated as untrusted data, not instructions.
            findings=wrap_untrusted(findings_summary),
            attack_surface=wrap_untrusted(
                "\n".join(f"- {e}" for e in self.memory.attack_surface) or "None discovered"
            ),
            technologies=wrap_untrusted(
                ", ".join(self.memory.context.get("technologies", [])) or "Unknown"
            ),
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
        """Parse AI response into structured decision.

        Hardening notes:
          * Try a strict JSON object first via Pydantic ``PlannerDecision``.
            That gives us schema validation, action whitelist, length caps
            and ``phase_transition`` for free.
          * Fallback: header-based extraction with bounded length and
            control-char stripping. Untrusted tool output that smuggled a
            fake ``NEXT_ACTION:`` line through to the LLM context cannot
            inject an arbitrary action name — the value is sanitized and
            matched against ``self._known_actions()``. Off-list ⇒ ``unknown``.
        """
        decision: Dict[str, Any] = {
            "next_action": "unknown",
            "parameters": {},
            "expected_outcome": "",
            "phase_transition": None,
        }

        if not isinstance(response, str) or not response.strip():
            return decision

        # ── 1. JSON-first attempt via Pydantic ────────────────────────────────
        json_match = re.search(r"\{[\s\S]*\}", response)
        if json_match:
            parsed = parse_or_none(json_match.group(0), PlannerDecision)
            if parsed is not None:
                return {
                    "next_action": parsed.next_action,
                    "parameters": parsed.parameters,
                    "expected_outcome": parsed.expected_outcome,
                    "phase_transition": parsed.phase_transition,
                }

        # ── 2. Header-based extraction (legacy schema) ────────────────────────
        action_match = re.search(
            r"NEXT_ACTION:\s*([^\n]{0,200})", response, re.IGNORECASE
        )
        if action_match:
            decision["next_action"] = self._normalize_action(action_match.group(1))

        params_match = re.search(
            r"PARAMETERS:\s*([^\n]{0,400})", response, re.IGNORECASE
        )
        if params_match:
            decision["parameters"] = strip_control_chars(params_match.group(1).strip())[:400]

        outcome_match = re.search(
            r"EXPECTED_OUTCOME:\s*([\s\S]{0,400})", response, re.IGNORECASE
        )
        if outcome_match:
            decision["expected_outcome"] = strip_control_chars(
                outcome_match.group(1).strip()
            )[:400]

        return decision

    def _normalize_action(self, raw: str) -> str:
        """Sanitize and whitelist-validate an action name."""
        cleaned = strip_control_chars(str(raw)).strip().lower()
        # Drop everything after first whitespace (prevents trailing instruction
        # smuggling like "subdomain_enumeration; rm -rf /").
        cleaned = cleaned.split()[0] if cleaned.split() else ""
        # Strip non-alphanumeric/underscore.
        cleaned = re.sub(r"[^a-z0-9_-]", "", cleaned)[:64]
        if not cleaned:
            return "unknown"
        # Allow termination keywords.
        if cleaned in ("done", "complete", "finish", "stop"):
            return cleaned
        if cleaned in self._known_actions():
            return cleaned
        # Off-list — log and downgrade rather than execute.
        self.logger.warning(
            f"Planner emitted unknown action '{cleaned}' — downgrading to 'unknown'"
        )
        return "unknown"

    def _known_actions(self) -> set:
        """Return the union of all phase-defined action names."""
        actions: set = set()
        for phase_actions in {
            "reconnaissance": [
                "subdomain_enumeration", "dns_enumeration",
                "technology_detection", "port_scanning",
            ],
            "scanning": [
                "service_detection", "vulnerability_scanning",
                "web_probing", "ssl_analysis",
            ],
            "analysis": [
                "correlate_findings", "risk_assessment",
                "false_positive_filter", "prioritize_vulns",
            ],
            "reporting": [
                "generate_report", "executive_summary", "remediation_plan",
            ],
        }.values():
            actions.update(phase_actions)
        return actions

"""
Analyst Agent
Interprets scan results and identifies security vulnerabilities
"""

from typing import Dict, Any, List
from datetime import datetime
from core.agent import BaseAgent
from core.memory import Finding
from ai.prompt_templates import (
    ANALYST_SYSTEM_PROMPT,
    ANALYST_INTERPRET_PROMPT,
    ANALYST_CORRELATION_PROMPT,
    ANALYST_FALSE_POSITIVE_PROMPT
)
from utils.helpers import parse_severity


class AnalystAgent(BaseAgent):
    """Agent that analyzes scan results and extracts security findings"""
    
    def __init__(self, config, gemini_client, memory):
        super().__init__("Analyst", config, gemini_client, memory)
    
    async def execute(self, tool_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze tool output and extract findings
        
        Args:
            tool_result: Results from a tool execution
        
        Returns:
            Dict with extracted findings and analysis
        """
        return await self.interpret_output(
            tool=tool_result["tool"],
            target=tool_result.get("target", "unknown"),
            command=tool_result.get("command", ""),
            output=tool_result.get("raw_output", "")
        )
    
    async def interpret_output(
        self,
        tool: str,
        target: str,
        command: str,
        output: str,
        execution_id: str = None
    ) -> Dict[str, Any]:
        """
        Interpret tool output and extract security findings
        
        Returns:
            Dict with findings, summary, and analysis
        """
        # Truncate very long outputs
        if len(output) > 5000:
            output = output[:5000] + "\n... (truncated)"
        
        # Gather memory context for richer analysis
        prior_findings_text = "\n".join(
            f"  [{f.severity.upper()}] {f.title}"
            for f in self.memory.findings[-10:]  # last 10 to keep prompt bounded
        ) or "None yet"
        technologies_text = ", ".join(self.memory.context.get("technologies", [])) or "Unknown"

        prompt = ANALYST_INTERPRET_PROMPT.format(
            tool=tool,
            target=target,
            command=command,
            execution_id=execution_id or "N/A",
            output=output,
            prior_findings=prior_findings_text,
            technologies=technologies_text,
        )
        
        result = await self.think(prompt, ANALYST_SYSTEM_PROMPT)
        
        # Parse findings from AI response and link to execution
        findings = self._parse_findings(
            result["response"], 
            tool, 
            target, 
            execution_id=execution_id,
            raw_output=output
        )
        
        # Add findings to memory
        for finding in findings:
            self.memory.add_finding(finding)
        
        self.log_action("AnalysisComplete", f"Found {len(findings)} issues from {tool}")
        
        return {
            "findings": findings,
            "summary": result["response"],
            "reasoning": result["reasoning"],
            "tool": tool
        }
    
    async def correlate_findings(self) -> Dict[str, Any]:
        """
        Correlate findings from multiple tools to build attack chains
        
        Returns:
            Strategic analysis of all findings
        """
        if not self.memory.findings:
            return {
                "correlations": [],
                "attack_chains": [],
                "priority_findings": []
            }
        
        # Format findings for AI
        tool_results = self._format_findings_for_correlation()
        
        prompt = ANALYST_CORRELATION_PROMPT.format(
            target=self.memory.target,
            tool_results=tool_results,
        )
        
        result = await self.think(prompt, ANALYST_SYSTEM_PROMPT)
        
        return {
            "analysis": result["response"],
            "reasoning": result["reasoning"],
            "findings_count": len(self.memory.findings)
        }
    
    async def check_false_positive(self, finding: Finding) -> Dict[str, Any]:
        """
        Evaluate if a finding is likely a false positive
        
        Returns:
            Dict with confidence score and recommendation
        """
        # Get context
        context = self.memory.get_context_for_ai()
        
        prompt = ANALYST_FALSE_POSITIVE_PROMPT.format(
            tool=finding.tool,
            severity=finding.severity,
            description=finding.description,
            evidence=finding.evidence[:500],
            context=context,
        )
        
        result = await self.think(prompt, ANALYST_SYSTEM_PROMPT)
        
        # Parse confidence from response
        confidence = self._extract_confidence(result["response"])
        
        return {
            "confidence": confidence,
            "analysis": result["response"],
            "reasoning": result["reasoning"],
            "recommendation": self._extract_recommendation(result["response"])
        }
    
    def _parse_findings(
        self, 
        ai_response: str, 
        tool: str, 
        target: str,
        execution_id: str = None,
        raw_output: str = ""
    ) -> List[Finding]:
        """Parse findings from AI analysis response and link to execution"""
        findings = []
        
        # Simple parsing - look for severity markers
        severity_markers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        
        lines = ai_response.split('\n')
        current_finding = None
        
        for line in lines:
            # Check if line starts a new finding
            for severity in severity_markers:
                if f"[{severity}]" in line or f"{severity}:" in line:
                    if current_finding:
                        findings.append(current_finding)
                    
                    # Extract title
                    title = line.split(']')[-1].strip() if ']' in line else line
                    
                    current_finding = Finding(
                        id=f"{tool}_{len(findings)}_{datetime.now().timestamp()}",
                        severity=severity.lower(),
                        title=title[:200],
                        description="",
                        evidence="",
                        tool=tool,
                        target=target,
                        timestamp=datetime.now().isoformat(),
                        execution_id=execution_id,
                        raw_evidence=raw_output[:2000] if raw_output else None
                    )
                    break
            
            # Accumulate description
            if current_finding and "Evidence:" not in line and "Impact:" not in line:
                current_finding.description += line + "\n"
            
            # Extract evidence
            if current_finding and "Evidence:" in line:
                evidence = line.split("Evidence:")[-1].strip()
                current_finding.evidence = evidence
        
        # Add last finding
        if current_finding:
            findings.append(current_finding)
        
        return findings
    
    def _format_findings_for_correlation(self) -> str:
        """Format findings for correlation analysis"""
        by_tool = {}
        for finding in self.memory.findings:
            if finding.tool not in by_tool:
                by_tool[finding.tool] = []
            by_tool[finding.tool].append(finding)
        
        formatted = []
        for tool, findings in by_tool.items():
            formatted.append(f"\n{tool.upper()}:")
            for f in findings:
                formatted.append(f"  [{f.severity.upper()}] {f.title}")
        
        return "\n".join(formatted)
    
    def _extract_confidence(self, response: str) -> int:
        """Extract confidence percentage from response"""
        if "CONFIDENCE:" in response:
            start = response.find("CONFIDENCE:") + len("CONFIDENCE:")
            end = start + 10
            confidence_str = response[start:end].strip()
            
            # Extract number
            import re
            match = re.search(r'(\d+)', confidence_str)
            if match:
                return int(match.group(1))
        
        return 50  # Default
    
    def _extract_recommendation(self, response: str) -> str:
        """Extract recommendation from response"""
        if "RECOMMENDATION:" in response:
            start = response.find("RECOMMENDATION:") + len("RECOMMENDATION:")
            recommendation = response[start:].strip()
            return recommendation.split('\n')[0]
        
        return "VERIFY_MANUALLY"

"""
Reporter Agent
Generates professional penetration testing reports
"""

from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime
from core.agent import BaseAgent
from core.cvss_calculator import validate_against_claimed
from ai.prompt_templates import (
    REPORTER_SYSTEM_PROMPT,
    REPORTER_EXECUTIVE_SUMMARY_PROMPT,
    REPORTER_TECHNICAL_FINDINGS_PROMPT,
    REPORTER_REMEDIATION_PROMPT,
    REPORTER_AI_TRACE_PROMPT,
    REPORTER_TOKEN_COST_SECTION_PROMPT,
)


class ReporterAgent(BaseAgent):
    """Agent that generates professional penetration testing reports"""
    
    def __init__(self, config, gemini_client, memory):
        super().__init__("Reporter", config, gemini_client, memory)
    
    async def execute(self, format: str = "markdown") -> Dict[str, Any]:
        """
        Generate a complete penetration testing report
        
        Args:
            format: Report format (markdown, html, json)
        
        Returns:
            Dict with report content and metadata
        """
        self.log_action("GeneratingReport", f"Format: {format}")
        
        # Generate all sections
        executive_summary = await self.generate_executive_summary()
        technical_findings = await self.generate_technical_findings()
        remediation = await self.generate_remediation_plan()
        ai_trace = await self.generate_ai_trace()
        
        # Assemble report
        if format == "markdown":
            report_content = self._assemble_markdown_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace
            )
        elif format == "html":
            report_content = self._assemble_html_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace
            )
        elif format == "json":
            report_content = self._assemble_json_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace
            )
        else:
            raise ValueError(f"Unknown format: {format}")
        
        return {
            "content": report_content,
            "format": format,
            "session_id": self.memory.session_id,
            "target": self.memory.target,
            "timestamp": datetime.now().isoformat()
        }
    
    async def generate_executive_summary(self) -> str:
        """Generate executive summary for non-technical audience"""
        summary = self.memory.get_findings_summary()
        
        # Get top critical issues
        critical_findings = self.memory.get_findings_by_severity("critical")
        high_findings = self.memory.get_findings_by_severity("high")
        
        top_issues = []
        for f in (critical_findings + high_findings)[:3]:
            top_issues.append(f"- {f.title}")
        
        # Derive an overall risk rating from finding counts
        if summary["critical"] > 0:
            risk_rating = "CRITICAL"
        elif summary["high"] > 3:
            risk_rating = "HIGH"
        elif summary["high"] > 0 or summary["medium"] > 5:
            risk_rating = "MEDIUM"
        else:
            risk_rating = "LOW"

        prompt = REPORTER_EXECUTIVE_SUMMARY_PROMPT.format(
            target=self.memory.target,
            scope="Full penetration test",
            assessment_date=datetime.now().strftime("%Y-%m-%d"),
            duration=self._calculate_duration(),
            session_id=self.memory.session_id,
            findings_count=len(self.memory.findings),
            critical_count=summary["critical"],
            high_count=summary["high"],
            medium_count=summary["medium"],
            low_count=summary["low"],
            info_count=summary["info"],
            risk_rating=risk_rating,
            top_issues="\n".join(top_issues) if top_issues else "No critical issues found",
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    async def generate_technical_findings(self) -> str:
        """Generate detailed technical findings section"""
        # Format findings for AI
        findings_text = self._format_findings_detailed()
        
        prompt = REPORTER_TECHNICAL_FINDINGS_PROMPT.format(
            findings=findings_text
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    async def generate_remediation_plan(self) -> str:
        """Generate prioritized remediation recommendations"""
        findings_text = self._format_findings_detailed()
        
        # Get affected systems
        affected = set()
        for f in self.memory.findings:
            affected.add(f.target)
        
        prompt = REPORTER_REMEDIATION_PROMPT.format(
            findings=findings_text,
            affected_systems="\n".join(f"- {s}" for s in affected)
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    async def generate_ai_trace(self) -> str:
        """Generate AI decision trace for transparency"""
        ai_decisions = "\n".join([
            f"- [{d['agent']}] {d['decision']} (Reasoning: {d['reasoning'][:100]}...)"
            for d in self.memory.ai_decisions
        ])
        
        workflow = f"Phase: {self.memory.current_phase}\nCompleted Actions: {len(self.memory.completed_actions)}"
        
        thinking_chain_text = "\n".join(
            f"  [Step {s.step_number} | {s.agent} | Round {s.round_number}] {s.conclusion[:150]}"
            for s in self.memory.thinking_chain
        ) or "No thinking steps recorded"

        prompt = REPORTER_AI_TRACE_PROMPT.format(
            ai_decisions=ai_decisions or "No AI decisions recorded",
            thinking_chain=thinking_chain_text,
            workflow=workflow,
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    def _assemble_markdown_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble Markdown report"""
        summary = self.memory.get_findings_summary()
        
        report = f"""# Penetration Test Report

## Target Information
- **Target**: {self.memory.target}
- **Session ID**: {self.memory.session_id}
- **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Duration**: {self._calculate_duration()}

## Executive Summary

{exec_summary}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['critical']} |
| High     | {summary['high']} |
| Medium   | {summary['medium']} |
| Low      | {summary['low']} |
| Info     | {summary['info']} |
| **Total** | **{len(self.memory.findings)}** |

## Technical Findings

{technical}

## Remediation Plan

{remediation}

## AI Decision Trace

{ai_trace}

## Tools Executed

{self._format_tool_executions()}

---
*Report generated by Guardian AI Pentest Tool*
"""
        return report
    
    def _assemble_html_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble HTML report"""
        summary = self.memory.get_findings_summary()
        
        # Convert markdown-style content to HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {self.memory.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .info {{ color: #95a5a6; }}
        .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>🔐 Penetration Test Report</h1>
    
    <div class="summary">
        <h3>Target Information</h3>
        <p><strong>Target:</strong> {self.memory.target}</p>
        <p><strong>Session ID:</strong> {self.memory.session_id}</p>
        <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Duration:</strong> {self._calculate_duration()}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <div>{self._markdown_to_html(exec_summary)}</div>
    
    <h2>Findings Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>{summary['critical']}</td></tr>
        <tr><td class="high">High</td><td>{summary['high']}</td></tr>
        <tr><td class="medium">Medium</td><td>{summary['medium']}</td></tr>
        <tr><td class="low">Low</td><td>{summary['low']}</td></tr>
        <tr><td class="info">Info</td><td>{summary['info']}</td></tr>
        <tr><th>Total</th><th>{len(self.memory.findings)}</th></tr>
    </table>
    
    <h2>Technical Findings</h2>
    <div>{self._markdown_to_html(technical)}</div>
    
    <h2>Remediation Plan</h2>
    <div>{self._markdown_to_html(remediation)}</div>
    
    <h2>AI Decision Trace</h2>
    <div>{self._markdown_to_html(ai_trace)}</div>
    
    <footer>
        <hr>
        <p><em>Report generated by Guardian AI Pentest Tool</em></p>
    </footer>
</body>
</html>"""
        return html
    
    def _assemble_json_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble JSON report"""
        import json
        from dataclasses import asdict
        
        report = {
            "metadata": {
                "target": self.memory.target,
                "session_id": self.memory.session_id,
                "timestamp": datetime.now().isoformat(),
                "duration": self._calculate_duration()
            },
            "executive_summary": exec_summary,
            "findings_summary": self.memory.get_findings_summary(),
            "findings": [asdict(f) for f in self.memory.findings],
            "technical_findings": technical,
            "remediation_plan": remediation,
            "ai_trace": ai_trace,
            "tool_executions": [asdict(t) for t in self.memory.tool_executions]
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _calculate_duration(self) -> str:
        """Calculate test duration"""
        start = datetime.fromisoformat(self.memory.start_time)
        end = datetime.now()
        duration = end - start
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        
        return f"{hours}h {minutes}m"
    
    def _format_findings_detailed(self) -> str:
        """Format findings for AI consumption.

        v3.0 change: drop the 200-char description/evidence truncation that
        forced the LLM to write reports from snippets. Pass the full evidence
        with a generous cap (4000 chars per field) and let the model
        summarise. This trades prompt size for reporting accuracy.
        """
        if not self.memory.findings:
            return "No findings"

        formatted: List[str] = []
        for f in self.memory.findings:
            # Validate any LLM-emitted CVSS vector against the recomputed
            # base score. Mismatches mean the LLM hallucinated a number;
            # we surface that so the prompt can ask the model to reconcile.
            cvss_note = ""
            if f.cvss_vector:
                _, ok = validate_against_claimed(f.cvss_vector, f.cvss_score)
                if not ok:
                    cvss_note = (
                        " [⚠️ CVSS vector does not match claimed score — "
                        "recompute before publishing]"
                    )
            formatted.append(
                f"\n[{f.severity.upper()}] {f.title}{cvss_note}\n"
                f"Tool: {f.tool}\n"
                f"Target: {f.target}\n"
                f"CVSS: {f.cvss_vector or 'N/A'} (score: {f.cvss_score or 'N/A'})\n"
                f"CWE: {f.cwe or 'N/A'}\n"
                f"Description: {f.description[:4000]}\n"
                f"Evidence: {f.evidence[:4000]}\n"
            )
        return "\n---\n".join(formatted)
    
    def _format_tool_executions(self) -> str:
        """Format tool executions for report"""
        if not self.memory.tool_executions:
            return "No tools executed"
        
        formatted = []
        for t in self.memory.tool_executions:
            formatted.append(f"- **{t.tool}**: {t.command} (Duration: {t.duration:.2f}s)")
        
        return "\n".join(formatted)
    
    def _markdown_to_html(self, markdown_text: str) -> str:
        """Render Markdown to HTML using the ``markdown`` library.

        Replaces the previous toy converter that broke on every finding
        with multiple bold spans (``str.replace('**', '<strong>')`` then
        ``str.replace('**', '</strong>')`` is a no-op on the second call —
        all bold markers became opening tags). The library is a small
        pure-Python dep with extension support.

        Falls back to a minimal escape-only renderer if the ``markdown``
        package is not installed (treats text as <pre>-formatted).
        """
        try:
            import markdown as _md
        except ImportError:
            from html import escape

            return f"<pre>{escape(markdown_text)}</pre>"
        return _md.markdown(
            markdown_text,
            extensions=["extra", "tables", "fenced_code", "sane_lists"],
        )

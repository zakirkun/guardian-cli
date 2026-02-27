"""
Nikto tool wrapper for web vulnerability scanning
"""

import re
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class NiktoTool(BaseTool):
    """Nikto web vulnerability scanner wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "nikto"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nikto command"""
        # Get config defaults
        config = self.config.get("tools", {}).get("nikto", {})
        
        # Workflow parameters override config
        # Priority: kwargs (workflow) > config > hardcoded defaults
        
        command = ["nikto"]

        # Host
        command.extend(["-h", target])

        # SSL
        if target.startswith("https"):
            command.append("-ssl")

        # Timeout (seconds per request)
        timeout = kwargs.get("timeout", config.get("timeout", 10))
        command.extend(["-timeout", str(timeout)])

        # Non-interactive (no prompts)
        command.append("-nointeractive")

        # NOTE: -Format json requires Perl JSON + XML::Writer which may not be installed.
        # Use plain text (default) — parse_output already handles text format.
        # NOTE: -Tuning without a valid argument list causes errors; omit to use defaults.

        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nikto text output"""
        results = {
            "vulnerabilities": [],
            "server_info": {},
            "findings_count": 0,
            "target": "",
            "scan_duration": None
        }
        
        vulnerabilities = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Extract target
            if "+ Target:" in line:
                results["target"] = line.split("Target:")[-1].strip()
            
            # Extract server info
            elif "+ Server:" in line:
                results["server_info"]["server"] = line.split("Server:")[-1].strip()
            
            # Extract findings (lines starting with +)
            elif line.startswith("+") and line != "+":
                # Skip informational lines
                if any(skip in line.lower() for skip in ["target ip:", "start time:", "end time:"]):
                    continue
                
                # Determine severity based on keywords
                severity = "info"
                if any(keyword in line.lower() for keyword in ["vulnerability", "exploit", "vulnerable"]):
                    severity = "high"
                elif any(keyword in line.lower() for keyword in ["security", "risk", "disclosure"]):
                    severity = "medium"
                elif any(keyword in line.lower() for keyword in ["config", "misconfiguration"]):
                    severity = "low"
                
                vuln = {
                    "description": line.lstrip("+").strip(),
                    "severity": severity,
                    "type": "web_vulnerability"
                }
                vulnerabilities.append(vuln)
        
        results["vulnerabilities"] = vulnerabilities
        results["findings_count"] = len(vulnerabilities)
        
        return results

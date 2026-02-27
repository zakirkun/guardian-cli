"""
Nuclei tool wrapper for vulnerability scanning
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class NucleiTool(BaseTool):
    """Nuclei vulnerability scanner wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "nuclei"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nuclei command"""
        # Get config defaults
        config = self.config.get("tools", {}).get("nuclei", {})
        
        # Workflow parameters override config
        # Priority: kwargs (workflow) > config > hardcoded defaults
        
        command = ["nuclei"]
        
        # Target
        if kwargs.get("from_file"):
            command.extend(["-l", kwargs["from_file"]])
        else:
            command.extend(["-u", target])
        
        # JSON output
        command.extend(["-jsonl"])
        
        # Severity filtering - workflow parameter or config or default
        severities = kwargs.get("severity", config.get("severity", ["critical", "high", "medium"]))
        if severities:
            # Convert list to comma-separated string if needed
            if isinstance(severities, list):
                command.extend(["-severity", ",".join(severities)])
            else:
                command.extend(["-severity", severities])
        
        # Templates path
        # subprocess does NOT expand '~' — must do it explicitly here
        templates_path = kwargs.get("templates_path", config.get("templates_path"))
        if templates_path:
            import os
            expanded = os.path.expanduser(str(templates_path))
            if os.path.exists(expanded):
                command.extend(["-t", expanded])
            # If path does not exist, omit -t so nuclei uses its own default

        # Silent mode
        command.append("-silent")

        # Rate limit
        rate_limit = kwargs.get("rate_limit", config.get("rate_limit", 150))
        command.extend(["-rate-limit", str(rate_limit)])

        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei JSON output"""
        results = {
            "vulnerabilities": [],
            "count": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        # Parse JSON lines
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                vuln = {
                    "template": data.get("template-id", "unknown"),
                    "name": data.get("info", {}).get("name", "Unknown"),
                    "severity": data.get("info", {}).get("severity", "info").lower(),
                    "matched_at": data.get("matched-at", ""),
                    "type": data.get("type", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", [])
                }
                
                results["vulnerabilities"].append(vuln)
                results["count"] += 1
                
                # Count by severity
                severity = vuln["severity"]
                if severity in results["by_severity"]:
                    results["by_severity"][severity] += 1
                
            except json.JSONDecodeError:
                continue
        
        return results

"""
httpx tool wrapper for HTTP probing
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class HttpxTool(BaseTool):
    """httpx HTTP probing wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "httpx"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build httpx command"""
        # Get config defaults
        config = self.config.get("tools", {}).get("httpx", {})
        
        # Workflow parameters override config
        # Priority: kwargs (workflow) > config > hardcoded defaults
        
        command = ["httpx"]
        
        # JSON output for easy parsing
        command.extend(["-json"])
        
        # Concurrency - httpx uses -concurrency not -threads
        threads = kwargs.get("threads", config.get("threads", 50))
        command.extend(["-concurrency", str(threads)])
        
        # Timeout - workflow parameter or config or default
        timeout = kwargs.get("timeout", config.get("timeout", 10))
        command.extend(["-timeout", str(timeout)])
        
        # Tech detection -workflow parameter or config or default
        if kwargs.get("tech_detect", config.get("tech_detect", True)):
            command.append("-tech-detect")
        
        # Status code - workflow parameter or config or default
        if kwargs.get("status_code", config.get("status_code", True)):
            command.append("-status-code")
        
        # Title - workflow parameter or config or default
        if kwargs.get("title", config.get("title", True)):
            command.append("-title")
        
        # Target (from stdin or direct)
        if kwargs.get("from_file"):
            command.extend(["-l", kwargs["from_file"]])
        else:
            command.extend(["-u", target])
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse httpx JSON output"""
        results = {
            "urls": [],
            "technologies": [],
            "status_codes": {},
            "titles": {}
        }
        
        # Parse JSON lines
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                url = data.get("url", "")
                
                if url:
                    results["urls"].append(url)
                    results["status_codes"][url] = data.get("status_code")
                    results["titles"][url] = data.get("title", "")
                    
                    # Extract technologies
                    if "tech" in data:
                        for tech in data["tech"]:
                            if tech not in results["technologies"]:
                                results["technologies"].append(tech)
                
            except json.JSONDecodeError:
                continue
        
        return results

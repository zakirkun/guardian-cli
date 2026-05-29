"""
WhatWeb tool wrapper for web technology fingerprinting
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class WhatWebTool(BaseTool):
    """WhatWeb technology fingerprinting wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "whatweb"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build whatweb command"""
        # Get config defaults
        config = self.config.get("tools", {}).get("whatweb", {})
        
        # Workflow parameters override config
        # Priority: kwargs (workflow) > config > hardcoded defaults
        
        command = ["whatweb"]

        # JSON output: pass as two separate args so subprocess splits correctly
        command.extend(["--log-json", "-"])

        # Aggression level (1-4)
        aggression = kwargs.get("aggression", config.get("aggression", 1))
        command.extend(["-a", str(aggression)])

        # Follow redirects
        if kwargs.get("follow_redirects", config.get("follow_redirects", True)):
            command.append("--follow-redirect")

        # Target
        command.append(target)

        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse whatweb JSON output"""
        results = {
            "technologies": [],
            "web_server": None,
            "programming_languages": [],
            "cms": None,
            "javascript_frameworks": [],
            "http_status": None,
            "plugins": []
        }
        
        # Parse JSON lines
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # HTTP status
                if "http_status" in data:
                    results["http_status"] = data["http_status"]
                
                # Extract plugins (technologies)
                plugins = data.get("plugins", {})
                
                for plugin_name, plugin_data in plugins.items():
                    tech = {
                        "name": plugin_name,
                        "version": None,
                        "categories": []
                    }
                    
                    # Extract version if available
                    if isinstance(plugin_data, dict):
                        version = plugin_data.get("version")
                        if version:
                            tech["version"] = version[0] if isinstance(version, list) else version
                    
                    results["plugins"].append(tech)
                    
                    # Categorize common technologies
                    plugin_lower = plugin_name.lower()
                    
                    if plugin_name in ["Apache", "nginx", "IIS", "LiteSpeed"]:
                        results["web_server"] = tech
                    elif plugin_name in ["PHP", "Python", "Ruby", "ASP.NET"]:
                        results["programming_languages"].append(plugin_name)
                    elif plugin_name in ["WordPress", "Joomla", "Drupal"]:
                        results["cms"] = tech
                    elif plugin_name in ["jQuery", "React", "Vue", "Angular"]:
                        results["javascript_frameworks"].append(plugin_name)
                    
                    results["technologies"].append(plugin_name)
                
            except json.JSONDecodeError:
                continue
        
        return results

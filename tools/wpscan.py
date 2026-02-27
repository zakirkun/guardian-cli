"""
WPScan tool wrapper for WordPress vulnerability scanning
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class WPScanTool(BaseTool):
    """WPScan WordPress vulnerability scanner wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "wpscan"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build wpscan command"""
        config = self.config.get("tools", {}).get("wpscan", {})
        
        command = ["wpscan"]
        
        # Target URL
        command.extend(["--url", target])
        
        # JSON output format (goes to stdout automatically)
        command.extend(["--format", "json"])

        # Skip update check (avoids stall on first run)
        command.append("--no-update")
        
        # API token for vulnerability database
        api_token = config.get("api_token", "")
        if api_token:
            command.extend(["--api-token", api_token])
        
        # Enumerate options
        enumerate = kwargs.get("enumerate", config.get("enumerate", "vp,vt,u"))
        # vp = Vulnerable plugins
        # vt = Vulnerable themes
        # u  = Users
        # ap = All plugins
        # at = All themes
        command.extend(["--enumerate", enumerate])
        
        # Threads
        threads = config.get("threads", 5)
        command.extend(["--max-threads", str(threads)])
        
        # Request timeout
        timeout = config.get("timeout", 60)
        command.extend(["--request-timeout", str(timeout)])
        
        # Connect timeout
        connect_timeout = config.get("connect_timeout", 30)
        command.extend(["--connect-timeout", str(connect_timeout)])
        
        # Detection mode
        detection_mode = config.get("detection_mode", "mixed")
        command.extend(["--detection-mode", detection_mode])
        
        # Random user agent
        if config.get("random_agent", True):
            command.append("--random-user-agent")
        
        # Disable SSL/TLS verification (for testing environments)
        if kwargs.get("disable_tls_checks"):
            command.append("--disable-tls-checks")
        
        # Plugins detection
        if kwargs.get("plugins_detection"):
            command.extend(["--plugins-detection", kwargs["plugins_detection"]])
        
        # Stealthy mode
        if kwargs.get("stealthy"):
            command.append("--stealthy")
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse wpscan JSON output"""
        results = {
            "wordpress_version": None,
            "vulnerabilities": [],
            "plugins": [],
            "themes": [],
            "users": [],
            "interesting_findings": []
        }
        
        try:
            if not output.strip():
                return results
            
            data = json.loads(output)
            
            # WordPress version
            if "version" in data:
                version_info = data["version"]
                results["wordpress_version"] = {
                    "number": version_info.get("number", "Unknown"),
                    "status": version_info.get("status", "Unknown"),
                    "found_by": version_info.get("found_by", "Unknown")
                }
                
                # Version vulnerabilities
                if "vulnerabilities" in version_info:
                    for vuln in version_info["vulnerabilities"]:
                        results["vulnerabilities"].append({
                            "title": vuln.get("title", ""),
                            "fixed_in": vuln.get("fixed_in", ""),
                            "references": vuln.get("references", {})
                        })
            
            # Plugins
            if "plugins" in data:
                for plugin_name, plugin_data in data["plugins"].items():
                    plugin_info = {
                        "name": plugin_name,
                        "version": plugin_data.get("version", {}).get("number", "Unknown"),
                        "vulnerabilities": []
                    }
                    
                    # Plugin vulnerabilities
                    if "vulnerabilities" in plugin_data:
                        for vuln in plugin_data["vulnerabilities"]:
                            plugin_info["vulnerabilities"].append({
                                "title": vuln.get("title", ""),
                                "fixed_in": vuln.get("fixed_in", ""),
                                "references": vuln.get("references", {})
                            })
                            
                            # Add to main vulnerabilities list
                            results["vulnerabilities"].append({
                                "plugin": plugin_name,
                                "title": vuln.get("title", ""),
                                "fixed_in": vuln.get("fixed_in", "")
                            })
                    
                    results["plugins"].append(plugin_info)
            
            # Themes
            if "themes" in data:
                for theme_name, theme_data in data["themes"].items():
                    theme_info = {
                        "name": theme_name,
                        "version": theme_data.get("version", {}).get("number", "Unknown"),
                        "vulnerabilities": []
                    }
                    
                    # Theme vulnerabilities
                    if "vulnerabilities" in theme_data:
                        for vuln in theme_data["vulnerabilities"]:
                            theme_info["vulnerabilities"].append({
                                "title": vuln.get("title", ""),
                                "fixed_in": vuln.get("fixed_in", "")
                            })
                    
                    results["themes"].append(theme_info)
            
            # Users
            if "users" in data:
                for user_id, user_data in data["users"].items():
                    results["users"].append({
                        "id": user_id,
                        "username": user_data.get("username", ""),
                        "found_by": user_data.get("found_by", "")
                    })
            
            # Interesting findings
            if "interesting_findings" in data:
                for finding in data["interesting_findings"]:
                    results["interesting_findings"].append({
                        "url": finding.get("url", ""),
                        "type": finding.get("type", ""),
                        "found_by": finding.get("found_by", "")
                    })
            
        except json.JSONDecodeError:
            pass
        
        return results

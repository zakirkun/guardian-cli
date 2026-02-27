"""
FFuf tool wrapper for fast web fuzzing
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class FFufTool(BaseTool):
    """FFuf fast web fuzzer wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "ffuf"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build ffuf command"""
        # Get config defaults
        config = self.config.get("tools", {}).get("ffuf", {})
        
        # Workflow parameters override config
        # Priority: kwargs (workflow) > config > hardcoded defaults
        
        command = ["ffuf"]
        
        # Target URL with FUZZ keyword
        if "FUZZ" not in target:
            target = f"{target}/FUZZ"
        command.extend(["-u", target])

        # Wordlist — fallback chain to find one that exists in the container
        import os
        default_wordlist = kwargs.get("wordlist", config.get("wordlist", ""))
        candidates = [
            default_wordlist,
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]
        wordlist = next((c for c in candidates if c and os.path.exists(c)), None)
        if not wordlist:
            # Last resort: write a tiny built-in list
            wordlist = "/tmp/guardian_ffuf_wordlist.txt"
            with open(wordlist, "w") as wf:
                wf.write("\n".join([
                    "admin", "login", "wp-admin", "api", "config", "backup",
                    ".env", "robots.txt", "sitemap.xml", "index.php", "phpinfo.php",
                    "wp-login.php", "xmlrpc.php", "readme.html", ".git", ".gitignore",
                ]))
        command.extend(["-w", wordlist])

        # Use -json for inline JSON output (no extra -o file needed)
        command.extend(["-json"])

        # Threads
        threads = kwargs.get("threads", config.get("threads", 40))
        command.extend(["-t", str(threads)])

        # Timeout
        timeout = kwargs.get("timeout", config.get("timeout", 10))
        command.extend(["-timeout", str(timeout)])
        
        # Filter by status code
        if "filter_status" in kwargs:
            command.extend(["-fc", kwargs["filter_status"]])
        elif "filter_status" in config:
            command.extend(["-fc", config["filter_status"]])
        
        # Match status code
        if "match_status" in kwargs:
            command.extend(["-mc", kwargs["match_status"]])
        elif "match_status" in config:
            command.extend(["-mc", config["match_status"]])
        else:
            # Default: match success codes
            command.extend(["-mc", "200,204,301,302,307,401,403"])
        
        # Filter by size
        if "filter_size" in kwargs:
            command.extend(["-fs", str(kwargs["filter_size"])])
        elif "filter_size" in config:
            command.extend(["-fs", str(config["filter_size"])])
        
        # Extensions
        if "extensions" in kwargs:
            command.extend(["-e", kwargs["extensions"]])
        elif "extensions" in config:
            command.extend(["-e", config["extensions"]])
        
        # Recursion
        if kwargs.get("recursion", config.get("recursion", False)):
            command.append("-recursion")
            recursion_depth = kwargs.get("recursion_depth", config.get("recursion_depth", 1))
            command.extend(["-recursion-depth", str(recursion_depth)])
        
        # Follow redirects
        if kwargs.get("follow_redirects", config.get("follow_redirects", False)):
            command.append("-r")
        
        # Rate limit (requests per second)
        if "rate" in kwargs:
            command.extend(["-rate", str(kwargs["rate"])])
        elif "rate" in config:
            command.extend(["-rate", str(config["rate"])])
        
        # Silent mode (less verbose)
        command.append("-s")
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output"""
        results = {
            "discovered_paths": [],
            "status_codes": {},
            "sizes": {},
            "total_requests": 0,
            "total_filtered": 0
        }
        
        try:
            # FFuf outputs JSON
            if not output.strip():
                return results
            
            data = json.loads(output)
            
            # Extract results
            if "results" in data:
                for result in data["results"]:
                    url = result.get("url", "")
                    status = result.get("status", 0)
                    length = result.get("length", 0)
                    
                    results["discovered_paths"].append({
                        "url": url,
                        "status": status,
                        "length": length,
                        "words": result.get("words", 0),
                        "lines": result.get("lines", 0)
                    })
                    
                    results["status_codes"][url] = status
                    results["sizes"][url] = length
            
            # Extract metadata
            if "config" in data:
                results["total_requests"] = data.get("config", {}).get("matcher", {}).get("count", 0)
            
        except json.JSONDecodeError:
            # Fallback: try to parse line by line if not valid JSON
            pass
        
        return results

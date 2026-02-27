"""
Gobuster tool wrapper for directory and file brute forcing
"""

import re
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class GobusterTool(BaseTool):
    """Gobuster directory/file brute forcing wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "gobuster"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build gobuster command"""
        # Get config defaults
        config = self.config.get("tools", {}).get("gobuster", {})
        
        # Workflow parameters override config
        # Priority: kwargs (workflow) > config > hardcoded defaults
        
        command = ["gobuster", "dir"]

        # Target URL
        command.extend(["-u", target])

        # Wordlist — prefer SecLists location available in the Docker image
        wordlist = kwargs.get(
            "wordlist",
            config.get(
                "wordlist",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
            ),
        )
        # Fallback chain: SecLists → dirb → gobuster builtin
        import os
        fallbacks = [
            wordlist,
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]
        for fb in fallbacks:
            if os.path.exists(fb):
                wordlist = fb
                break
        command.extend(["-w", wordlist])

        # Threads
        threads = kwargs.get("threads", config.get("threads", 10))
        command.extend(["-t", str(threads)])

        # NOTE: Do NOT set -s (status_codes allowlist) together with -b (blacklist).
        # gobuster sets -b 404 by default; setting -s at the same time causes an error.
        # Use -b to add extra codes to blacklist if needed.

        # Extensions
        extensions = kwargs.get("extensions", config.get("extensions", ""))
        if extensions:
            command.extend(["-x", extensions])

        # Timeout
        timeout = kwargs.get("timeout", config.get("timeout", 10))
        command.extend(["--timeout", f"{timeout}s"])

        # Quiet mode (suppress progress bar noise)
        command.append("-q")

        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        results = {
            "directories": [],
            "files": [],
            "found_count": 0,
            "status_codes": {}
        }
        
        # Parse each line
        for line in output.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('='):
                continue
            
            # e.g.: /admin (Status: 200) [Size: 1234]
            match = re.search(r'(/[^\s]*)\s+\(Status:\s+(\d+)\)', line)
            if match:
                path = match.group(1)
                status = match.group(2)
                
                # Extract size if available
                size_match = re.search(r'\[Size:\s+(\d+)\]', line)
                size = int(size_match.group(1)) if size_match else None
                
                finding = {
                    "path": path,
                    "status_code": int(status),
                    "size": size,
                    "url": f"{line.split()[0] if not line.startswith('/') else path}"
                }
                
                # Categorize as directory or file
                if path.endswith('/') or status in ['301', '302']:
                    results["directories"].append(finding)
                else:
                    results["files"].append(finding)
                
                results["found_count"] += 1
                
                # Track status codes
                if status not in results["status_codes"]:
                    results["status_codes"][status] = 0
                results["status_codes"][status] += 1
        
        return results

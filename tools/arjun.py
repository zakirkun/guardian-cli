from typing import List, Dict, Any
from tools.base_tool import BaseTool
import json
import os

class ArjunTool(BaseTool):
    """Wrapper for Arjun - HTTP Parameter Discovery Tool"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        # arjun -u <target> -o <output.json> -q
        # Note: arjun uses -o for JSON output file, NOT --json
        self.output_file = f"arjun_{self._get_timestamp()}.json"
        cmd = ["arjun", "-u", target, "-o", self.output_file, "-q"]

        # HTTP method
        if kwargs.get("method"):
            cmd.extend(["-m", kwargs["method"]])

        # Threads
        if kwargs.get("threads"):
            cmd.extend(["-t", str(kwargs["threads"])])

        # Delay between requests
        if kwargs.get("delay"):
            cmd.extend(["--delay", str(kwargs["delay"])])

        return cmd
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {
            "params": [],
            "method": "GET",
            "raw_output": output
        }
        
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    data = json.load(f)
                    
                # Arjun JSON format varies slightly by version, handle common structures
                # Typical: {"url": "...", "params": ["id", "user"], "method": "GET"}
                # Or dictionary of results
                
                if isinstance(data, dict):
                    # Check if it's the direct result format
                    if "params" in data:
                        result["params"] = data["params"]
                        result["method"] = data.get("method", "GET")
                    else:
                        # Iterate through keys (URLs) if it's a multi-target result
                        for url, info in data.items():
                            if isinstance(info, dict) and "params" in info:
                                result["params"].extend(info["params"])
                                result["method"] = info.get("method", "GET")
            
                # Cleanup
                os.remove(self.output_file)
            except Exception as e:
                self.logger.error(f"Error parsing Arjun JSON: {e}")
                
        return result

    def _get_timestamp(self):
        import time
        return int(time.time())

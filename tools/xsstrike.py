from typing import List, Dict, Any
from tools.base_tool import BaseTool
import json
import re

class XSStrikeTool(BaseTool):
    """Wrapper for XSStrike - Advanced XSS Detection Suite"""

    # Common installation paths in Docker / Kali images
    _SCRIPT_PATHS = [
        "/opt/xsstrike/xsstrike.py",
        "/usr/share/xsstrike/xsstrike.py",
        "/opt/XSStrike/xsstrike.py",
    ]

    def __init__(self, config):
        import shutil, os
        # Find script path — prefer python3 invocation over a shim binary
        self._script = None
        for p in self._SCRIPT_PATHS:
            if os.path.exists(p):
                self._script = p
                break
        # Set tool_name BEFORE calling super so is_available check uses it
        self.tool_name = "xsstrike"
        super().__init__(config)

    def _check_installation(self) -> bool:
        import shutil, os
        # Available if either the script exists or the binary is in PATH
        return any(os.path.exists(p) for p in self._SCRIPT_PATHS) or bool(shutil.which("xsstrike"))

    def get_command(self, target: str, **kwargs) -> List[str]:
        import shutil
        # Build invocation: prefer python3 script, fall back to binary
        if self._script:
            cmd = ["python3", self._script, "-u", target]
        else:
            cmd = ["xsstrike", "-u", target]

        if kwargs.get("crawl", False):
            cmd.append("--crawl")

        if kwargs.get("level"):
            cmd.extend(["-l", str(kwargs["level"])])

        if kwargs.get("headers"):
            cmd.extend(["--headers", kwargs["headers"]])

        # --json is supported in XSStrike v3.1.5
        if kwargs.get("json_output", False):
            cmd.append("--json")

        if kwargs.get("timeout"):
            cmd.extend(["--timeout", str(kwargs["timeout"])])

        return cmd
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {
            "vulnerabilities": [],
            "crawled_urls": [],
            "raw_output": output
        }
        
        # Try to parse JSON lines if mixed in output
        for line in output.splitlines():
            try:
                if line.strip().startswith("{") and "vulnerable" in line:
                    data = json.loads(line)
                    if data.get("vulnerable"):
                        result["vulnerabilities"].append({
                            "url": data.get("url"),
                            "param": data.get("param"),
                            "vector": data.get("vector"),
                            "payload": data.get("payload")
                        })
            except json.JSONDecodeError:
                pass
                
        # Fallback: Regex parsing for standard output
        if not result["vulnerabilities"]:
            # Pattern for payloads found
            payloads = re.findall(r"Payload: (.*)", output)
            vectors = re.findall(r"Vector: (.*)", output)
            
            for i, payload in enumerate(payloads):
                result["vulnerabilities"].append({
                    "payload": payload,
                    "vector": vectors[i] if i < len(vectors) else "Unknown"
                })

        return result

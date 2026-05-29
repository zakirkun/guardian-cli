from typing import List, Dict, Any
from tools.base_tool import BaseTool
import json
import re

class CMSeekTool(BaseTool):
    """Wrapper for CMSeek - CMS Detection and Exploitation Tool"""

    def __init__(self, config):
        import shutil
        # CMSeek can be 'cmseek', 'cmseek.py' or a python script
        if shutil.which("cmseek"):
            self._bin = "cmseek"
        elif shutil.which("cmseek.py"):
            self._bin = "cmseek.py"
        else:
            self._bin = "cmseek"   # will fail is_available gracefully
        self.tool_name = self._bin
        super().__init__(config)

    def get_command(self, target: str, **kwargs) -> List[str]:
        # python3 cmseek.py -u <target>
        # Assuming installed as 'cmseek' command or python script
        cmd = [self._bin, "-u", target]
        
        if kwargs.get("batch"):
            cmd.append("--batch")
            
        if kwargs.get("random_agent"):
            cmd.append("--random-agent")
            
        if kwargs.get("light_scan"):
             cmd.append("--light-scan")
             
        return cmd
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {
            "cms": None,
            "version": None,
            "url": None,
            "raw_output": output
        }
        
        # CMSeek output parsing (JSON output support is limited in some versions, parsing stdout is safer)
        # Look for "CMS: WordPress" etc.
        
        cms_match = re.search(r"CMS Detected: (.*)", output, re.IGNORECASE)
        if cms_match:
            result["cms"] = cms_match.group(1).strip()
            
        version_match = re.search(r"CMS Version: (.*)", output, re.IGNORECASE)
        if version_match:
            result["version"] = version_match.group(1).strip()
            
        url_match = re.search(r"Target: (.*)", output, re.IGNORECASE)
        if url_match:
            result["url"] = url_match.group(1).strip()

        return result

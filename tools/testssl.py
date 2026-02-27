"""
TestSSL tool wrapper for SSL/TLS testing
"""

import re
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class TestSSLTool(BaseTool):
    """TestSSL.sh SSL/TLS testing wrapper"""
    
    def __init__(self, config):
        # resolve the actual binary before calling super()
        import shutil
        if shutil.which("testssl"):
            self._bin = "testssl"
        elif shutil.which("testssl.sh"):
            self._bin = "testssl.sh"
        else:
            self._bin = "testssl"   # will fail is_available check gracefully
        self.tool_name = self._bin
        super().__init__(config)
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build testssl command"""
        command = [self._bin]
        
        # Machine-readable output
        command.append("--jsonfile=-")
        
        # Severity level
        severity = kwargs.get("severity", "HIGH")
        command.extend(["--severity", severity])
        
        # Fast mode
        if kwargs.get("fast", False):
            command.append("--fast")
        
        # Quiet mode
        command.append("--quiet")
        
        # Target (host:port or URL)
        command.append(target)
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse testssl JSON output"""
        results = {
            "ssl_enabled": False,
            "tls_versions": [],
            "cipher_suites": [],
            "vulnerabilities": [],
            "certificate_info": {},
            "grade": None,
            "issues_count": 0
        }
        
        try:
            import json
            
            # TestSSL outputs JSON lines
            for line in output.strip().split('\n'):
                if not line or not line.startswith('{'):
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Extract certificate info
                    if data.get("id") == "cert_commonName":
                        results["certificate_info"]["common_name"] = data.get("finding")
                    
                    elif data.get("id") == "cert_notAfter":
                        results["certificate_info"]["expiry"] = data.get("finding")
                    
                    # Extract protocols
                    elif "SSLv" in data.get("id", "") or "TLS" in data.get("id", ""):
                        if data.get("finding") == "offered":
                            protocol = data.get("id").replace("_", " ")
                            results["tls_versions"].append(protocol)
                    
                    # Extract vulnerabilities
                    elif data.get("severity") in ["HIGH", "CRITICAL", "MEDIUM"]:
                        vuln = {
                            "name": data.get("id"),
                            "severity": data.get("severity").lower(),
                            "finding": data.get("finding"),
                            "cve": data.get("cve", "")
                        }
                        results["vulnerabilities"].append(vuln)
                        results["issues_count"] += 1
                    
                except json.JSONDecodeError:
                    continue
            
            results["ssl_enabled"] = len(results["tls_versions"]) > 0
            
        except Exception as e:
            # Fallback to text parsing if JSON fails
            if "ssl" in output.lower() or "tls" in output.lower():
                results["ssl_enabled"] = True
        
        return results

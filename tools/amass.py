"""
Amass tool wrapper for advanced network mapping and asset discovery
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class AmassTool(BaseTool):
    """Amass network mapping and subdomain enumeration wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "amass"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build amass command"""
        config = self.config.get("tools", {}).get("amass", {})
        
        command = ["amass"]
        
        # Subcommand - default to enum (enumeration)
        subcommand = kwargs.get("subcommand", "enum")
        command.append(subcommand)
        
        # Domain
        command.extend(["-d", target])
        
        # JSON lines output
        command.append("-json")
        
        # Active vs Passive mode
        mode = config.get("mode", "passive")
        if mode == "passive" or kwargs.get("passive"):
            command.append("-passive")
        else:
            # Active mode (includes techniques like DNS zone transfers, brute force)
            command.append("-active")
        
        # Timeout
        timeout = config.get("timeout", 30)
        command.extend(["-timeout", str(timeout)])
        
        # Max DNS queries per minute (rate limiting)
        if "max_dns_queries" in config:
            command.extend(["-max-dns-queries", str(config["max_dns_queries"])])
        
        # Brute forcing (if active mode)
        if mode == "active" and kwargs.get("brute"):
            command.append("-brute")
        
        # Include IP addresses
        command.append("-ip")
        
        # Sources to exclude (if any)
        if "exclude_sources" in kwargs:
            command.extend(["-exclude", kwargs["exclude_sources"]])
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse amass JSON output"""
        results = {
            "subdomains": [],
            "ip_addresses": [],
            "asns": [],
            "cidrs": [],
            "relationships": []
        }
        
        # Parse JSON lines
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # Extract subdomain
                name = data.get("name", "")
                if name and name not in results["subdomains"]:
                    results["subdomains"].append(name)
                
                # Extract IP addresses
                if "addresses" in data:
                    for addr in data["addresses"]:
                        ip = addr.get("ip", "")
                        if ip and ip not in results["ip_addresses"]:
                            results["ip_addresses"].append(ip)
                        
                        # Extract ASN
                        asn = addr.get("asn", 0)
                        if asn and asn not in results["asns"]:
                            results["asns"].append(asn)
                        
                        # Extract CIDR
                        cidr = addr.get("cidr", "")
                        if cidr and cidr not in results["cidrs"]:
                            results["cidrs"].append(cidr)
                
                # Relationship data
                if "domain" in data and "name" in data:
                    relationship = {
                        "domain": data.get("domain", ""),
                        "subdomain": data.get("name", ""),
                        "source": data.get("source", "unknown")
                    }
                    results["relationships"].append(relationship)
                
            except json.JSONDecodeError:
                continue
        
        return results

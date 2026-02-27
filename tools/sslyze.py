"""
SSLyze tool wrapper for advanced SSL/TLS security testing
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class SSLyzeTool(BaseTool):
    """SSLyze SSL/TLS security testing wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "sslyze"
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build sslyze command"""
        config = self.config.get("tools", {}).get("sslyze", {})
        
        command = ["sslyze"]
        
        # Parse target (host:port)
        if ":" in target:
            host, port = target.rsplit(":", 1)
        else:
            host = target
            port = "443"
        
        # Target specification
        command.append(f"{host}:{port}")
        
        # JSON output
        command.append("--json_out=-")
        
        # Regular scan (all checks)
        if kwargs.get("regular"):
            command.append("--regular")
        else:
            # Individual checks
            
            # Certificate information
            command.append("--certinfo")
            
            # SSL 2.0/3.0 (legacy protocols)
            command.append("--sslv2")
            command.append("--sslv3")
            
            # TLS protocols
            command.append("--tlsv1")
            command.append("--tlsv1_1")
            command.append("--tlsv1_2")
            command.append("--tlsv1_3")
            
            # Cipher suites
            command.append("--reneg")  # Renegotiation
            command.append("--resum")  # Session resumption
            
            # Vulnerabilities
            command.append("--heartbleed")
            command.append("--robot")
            command.append("--openssl_ccs")  # OpenSSL CCS injection
            
            # Compression (CRIME attack)
            command.append("--compression")
            
            # HTTP security headers
            command.append("--http_headers")
        
        # Note: sslyze does not support --timeout or --quiet flags
        # Remove them to avoid 'unrecognized arguments' errors

        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse sslyze JSON output"""
        results = {
            "certificate": {},
            "protocols": {},
            "cipher_suites": {},
            "vulnerabilities": [],
            "security_headers": {},
            "issues": []
        }
        
        try:
            if not output.strip():
                return results
            
            data = json.loads(output)
            
            # Get server scan results
            server_scan_results = data.get("server_scan_results", [])
            if not server_scan_results:
                return results
            
            scan_result = server_scan_results[0]
            scan_commands = scan_result.get("scan_commands_results", {})
            
            # Certificate information
            if "certificate_info" in scan_commands:
                cert_info = scan_commands["certificate_info"]
                cert_deployments = cert_info.get("certificate_deployments", [])
                
                if cert_deployments:
                    cert_deployment = cert_deployments[0]
                    verified_chain = cert_deployment.get("verified_certificate_chain", [])
                    
                    if verified_chain:
                        leaf_cert = verified_chain[0]
                        results["certificate"] = {
                            "subject": leaf_cert.get("subject", {}),
                            "issuer": leaf_cert.get("issuer", {}),
                            "not_valid_before": leaf_cert.get("not_valid_before", ""),
                            "not_valid_after": leaf_cert.get("not_valid_after", ""),
                            "serial_number": leaf_cert.get("serial_number", ""),
                            "signature_algorithm": leaf_cert.get("signature_algorithm_oid", {}).get("name", "")
                        }
                    
                    # Certificate validation
                    validation_result = cert_deployment.get("leaf_certificate_subject_matches_hostname", False)
                    if not validation_result:
                        results["issues"].append("Certificate hostname mismatch")
            
            # Protocol support
            protocol_checks = ["ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]
            for protocol_key in protocol_checks:
                if protocol_key in scan_commands:
                    protocol_result = scan_commands[protocol_key]
                    is_supported = protocol_result.get("is_tls_version_supported", False)
                    
                    protocol_name = protocol_key.replace("_", ".").upper()
                    results["protocols"][protocol_name] = is_supported
                    
                    # Flag weak protocols
                    if is_supported and protocol_key in ["ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1"]:
                        results["vulnerabilities"].append({
                            "name": f"Weak protocol: {protocol_name}",
                            "severity": "high" if "ssl" in protocol_key else "medium"
                        })
            
            # Vulnerabilities
            vuln_checks = {
                "heartbleed": "Heartbleed (CVE-2014-0160)",
                "robot": "ROBOT attack",
                "openssl_ccs_injection": "OpenSSL CCS Injection",
                "tls_compression": "CRIME attack (TLS Compression)"
            }
            
            for vuln_key, vuln_name in vuln_checks.items():
                if vuln_key in scan_commands:
                    vuln_result = scan_commands[vuln_key]
                    
                    if vuln_key == "heartbleed":
                        is_vulnerable = vuln_result.get("is_vulnerable_to_heartbleed", False)
                    elif vuln_key == "robot":
                        robot_result = vuln_result.get("robot_result_enum", "")
                        is_vulnerable = "VULNERABLE" in robot_result
                    elif vuln_key == "openssl_ccs_injection":
                        is_vulnerable = vuln_result.get("is_vulnerable_to_ccs_injection", False)
                    elif vuln_key == "tls_compression":
                        is_vulnerable = vuln_result.get("supports_compression", False)
                    else:
                        is_vulnerable = False
                    
                    if is_vulnerable:
                        results["vulnerabilities"].append({
                            "name": vuln_name,
                            "severity": "critical"
                        })
            
            # HTTP security headers
            if "http_headers" in scan_commands:
                headers_result = scan_commands["http_headers"]
                strict_transport_security = headers_result.get("strict_transport_security_header")
                
                if strict_transport_security:
                    results["security_headers"]["HSTS"] = strict_transport_security.get("max_age", 0)
                else:
                    results["issues"].append("Missing HSTS header")
            
        except json.JSONDecodeError:
            pass
        except (KeyError, IndexError, TypeError):
            pass
        
        return results

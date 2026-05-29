"""
Scope validation and target verification
Ensures all scanning is within authorized boundaries
"""

import ipaddress
import re
import socket
from typing import List, Set, Optional
from pathlib import Path
from urllib.parse import urlparse

from utils.logger import get_logger


# Default blacklist applied even when config omits CIDRs.
# Covers IPv4 + IPv6 loopback, link-local, private (RFC1918), unique-local (ULA),
# carrier-grade NAT, and metadata services (AWS/GCP/Azure 169.254.169.254).
_HARDCODED_BLACKLIST_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "0.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


class ScopeValidator:
    """Validates targets against authorized scope and blacklists"""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = get_logger()
        
        # Load blacklisted IP ranges (config + hardcoded defaults — defense in depth).
        self.blacklist_networks: List[ipaddress._BaseNetwork] = []
        configured = list(config.get("scope", {}).get("blacklist", []))
        for cidr in configured + _HARDCODED_BLACKLIST_CIDRS:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net not in self.blacklist_networks:
                    self.blacklist_networks.append(net)
            except ValueError as e:
                self.logger.warning(f"Invalid blacklist CIDR: {cidr} - {e}")

        # Cache hostname -> resolved IPs (avoid repeat DNS during validation loops).
        self._dns_cache: dict[str, List[str]] = {}
        
        # Load authorized scope (if provided)
        self.authorized_domains: Set[str] = set()
        self.authorized_ips: Set[str] = set()
        self.authorized_networks: List[ipaddress.ip_network] = []
    
    def load_scope_file(self, scope_file: Path) -> bool:
        """Load authorized scope from file"""
        try:
            with open(scope_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try to parse as IP/CIDR
                    if self._is_ip_or_cidr(line):
                        try:
                            if '/' in line:
                                self.authorized_networks.append(ipaddress.ip_network(line))
                            else:
                                self.authorized_ips.add(line)
                        except ValueError:
                            self.logger.warning(f"Invalid IP/CIDR in scope: {line}")
                    else:
                        # Treat as domain
                        self.authorized_domains.add(line.lower())
            
            self.logger.info(f"Loaded scope from {scope_file}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load scope file: {e}")
            return False
    
    def validate_target(self, target: str) -> tuple[bool, Optional[str]]:
        """
        Validate a target against scope and blacklists
        Returns (is_valid, reason)
        """
        # Parse target
        target = target.strip()
        
        # Check if it's a URL
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc
        else:
            host = target
        
        # Check if blacklisted
        if self._is_blacklisted(host):
            reason = f"Target {host} is in blacklisted range"
            self.logger.log_security_event("SCOPE_VIOLATION", "CRITICAL", reason)
            return False, reason
        
        # If scope file is required, check authorization
        if self.config.get("scope", {}).get("require_scope_file", False):
            if not self._is_authorized(host):
                reason = f"Target {host} not in authorized scope"
                self.logger.log_security_event("SCOPE_VIOLATION", "HIGH", reason)
                return False, reason
        
        return True, None
    
    def _is_blacklisted(self, host: str) -> bool:
        """Check if host (IP or hostname) resolves to any blacklisted range.

        For hostnames, resolves via DNS (all returned addresses) so a domain
        pointing at an internal IP cannot bypass the blacklist. Resolution
        failures are treated as blacklisted (fail-closed) — better to refuse
        an unresolvable target than to scan something we cannot vet.
        """
        host_lower = host.lower().strip()

        # Always block literal localhost/loopback aliases that are not valid IPs.
        if host_lower in ("localhost", "ip6-localhost", "ip6-loopback"):
            return True

        # Try as literal IP first.
        try:
            ip = ipaddress.ip_address(host)
            for network in self.blacklist_networks:
                if ip.version == network.version and ip in network:
                    return True
            return False
        except ValueError:
            pass  # Fall through to DNS resolution.

        # Resolve hostname → IPs and check each against blacklist.
        ips = self._resolve(host_lower)
        if ips is None:
            self.logger.log_security_event(
                "SCOPE_VIOLATION",
                "HIGH",
                f"DNS resolution failed for {host} — refusing (fail-closed)",
            )
            return True

        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            for network in self.blacklist_networks:
                if ip.version == network.version and ip in network:
                    self.logger.log_security_event(
                        "SCOPE_VIOLATION",
                        "CRITICAL",
                        f"Hostname {host} resolved to {ip_str} (in {network})",
                    )
                    return True
        return False

    def _resolve(self, host: str) -> Optional[List[str]]:
        """Resolve hostname to list of IPv4/IPv6 strings. None on failure."""
        if host in self._dns_cache:
            return self._dns_cache[host]
        try:
            infos = socket.getaddrinfo(
                host,
                None,
                proto=socket.IPPROTO_TCP,
            )
        except (socket.gaierror, socket.herror, UnicodeError) as e:
            self.logger.warning(f"DNS resolution failed for {host}: {e}")
            self._dns_cache[host] = []
            return None
        ips = sorted({info[4][0] for info in infos})
        self._dns_cache[host] = ips
        return ips
    
    def _is_authorized(self, host: str) -> bool:
        """Check if host is in authorized scope"""
        # Check if IP
        try:
            ip = ipaddress.ip_address(host)
            
            # Check authorized IPs
            if str(ip) in self.authorized_ips:
                return True
            
            # Check authorized networks
            for network in self.authorized_networks:
                if ip in network:
                    return True
        except ValueError:
            # Not an IP, check as domain
            host_lower = host.lower()
            
            # Exact match
            if host_lower in self.authorized_domains:
                return True
            
            # Subdomain match (*.example.com)
            for domain in self.authorized_domains:
                if domain.startswith('*.'):
                    pattern = domain[2:]  # Remove *.
                    if host_lower.endswith(pattern):
                        return True
                elif domain.startswith('.'):
                    # Matches domain and all subdomains
                    if host_lower.endswith(domain) or host_lower == domain[1:]:
                        return True
        
        return False
    
    def _is_ip_or_cidr(self, value: str) -> bool:
        """Check if value is an IP address or CIDR notation"""
        try:
            if '/' in value:
                ipaddress.ip_network(value)
            else:
                ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def add_authorized_target(self, target: str):
        """Dynamically add a target to authorized scope"""
        if self._is_ip_or_cidr(target):
            try:
                if '/' in target:
                    self.authorized_networks.append(ipaddress.ip_network(target))
                else:
                    self.authorized_ips.add(target)
            except ValueError:
                self.logger.warning(f"Invalid IP/CIDR: {target}")
        else:
            self.authorized_domains.add(target.lower())
        
        self.logger.info(f"Added to authorized scope: {target}")

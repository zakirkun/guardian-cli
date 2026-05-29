"""Tests for utils.scope_validator — focused on the SSRF-class bypass fix."""

from __future__ import annotations

import socket
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from utils.scope_validator import ScopeValidator


def _info(ip: str) -> tuple:
    """Build a getaddrinfo-shaped tuple for one IP."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))


class TestLiteralIp:
    def test_blocks_localhost(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        ok, _ = v.validate_target("127.0.0.1")
        assert ok is False

    def test_blocks_rfc1918(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        for ip in ("10.0.0.5", "172.16.1.1", "192.168.1.10"):
            ok, _ = v.validate_target(ip)
            assert ok is False, f"{ip} should be blocked"

    def test_blocks_metadata_service(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        ok, _ = v.validate_target("169.254.169.254")
        assert ok is False

    def test_blocks_ipv6_loopback(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        ok, _ = v.validate_target("::1")
        assert ok is False

    def test_blocks_ipv6_link_local(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        ok, _ = v.validate_target("fe80::1")
        assert ok is False

    def test_blocks_ipv6_ula(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        ok, _ = v.validate_target("fc00::1")
        assert ok is False

    def test_allows_public_ip(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", return_value=[_info("8.8.8.8")]):
            ok, _ = v.validate_target("8.8.8.8")
        assert ok is True


class TestDnsBypass:
    """The original bug: hostname → internal IP slipped through."""

    def test_blocks_domain_resolving_to_rfc1918(
        self, base_config: Dict[str, Any]
    ) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", return_value=[_info("10.0.0.5")]):
            ok, reason = v.validate_target("attacker.example.com")
        assert ok is False
        assert reason and "blacklisted" in reason.lower()

    def test_blocks_domain_resolving_to_loopback(
        self, base_config: Dict[str, Any]
    ) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", return_value=[_info("127.0.0.1")]):
            ok, _ = v.validate_target("evil.example.com")
        assert ok is False

    def test_blocks_when_any_dns_answer_is_internal(
        self, base_config: Dict[str, Any]
    ) -> None:
        # Round-robin DNS: one public IP + one internal — must reject.
        v = ScopeValidator(base_config)
        with patch(
            "socket.getaddrinfo",
            return_value=[_info("8.8.8.8"), _info("10.0.0.5")],
        ):
            ok, _ = v.validate_target("mixed.example.com")
        assert ok is False

    def test_blocks_ipv6_dns_to_link_local(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", return_value=[_info("fe80::1")]):
            ok, _ = v.validate_target("v6evil.example.com")
        assert ok is False

    def test_localhost_alias_blocked(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        ok, _ = v.validate_target("localhost")
        assert ok is False

    def test_dns_failure_is_fail_closed(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nx")):
            ok, _ = v.validate_target("does-not-exist.invalid")
        assert ok is False  # fail-closed

    def test_dns_cache_used(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", return_value=[_info("8.8.8.8")]) as m:
            v.validate_target("cached.example.com")
            v.validate_target("cached.example.com")
        # Cache means second call doesn't re-resolve.
        assert m.call_count == 1


class TestUrlParsing:
    def test_extracts_hostname_from_url(self, base_config: Dict[str, Any]) -> None:
        v = ScopeValidator(base_config)
        with patch("socket.getaddrinfo", return_value=[_info("10.0.0.5")]):
            ok, _ = v.validate_target("https://attacker.example.com/path")
        assert ok is False

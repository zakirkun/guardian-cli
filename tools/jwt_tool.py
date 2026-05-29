"""
jwt_tool wrapper — JWT analysis and attack toolkit.

Tests the canonical JWT weaknesses: ``alg=none``, alg confusion (RS256→HS256),
weak HMAC keys, claim injection, kid traversal. Risk class: ``intrusive`` —
forges tokens and sends them at the target.

The wrapper accepts the JWT directly as ``target`` or via the ``token``
parameter, plus an optional ``url`` to actually replay against. By default
runs in ``-T`` (tamper) read-only mode; replay mode requires explicit
``replay_url``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class JwtTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Upstream binary is "jwt_tool" or "jwt_tool.py" depending on install.
        self.tool_name = "jwt_tool"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("jwt_tool", {})
        token = kwargs.get("token", target)
        cmd: List[str] = ["jwt_tool", token]

        # ``mode`` selects the attack: scan|tamper|verify|crack
        mode = kwargs.get("mode", cfg.get("mode", "scan"))
        if mode == "scan":
            cmd.extend(["-M", "at"])  # all-tests
        elif mode == "tamper":
            cmd.append("-T")
        elif mode == "crack":
            wordlist = kwargs.get("wordlist", cfg.get("wordlist"))
            if wordlist:
                cmd.extend(["-C", "-d", str(wordlist)])

        replay_url = kwargs.get("replay_url")
        if replay_url:
            cmd.extend(["-t", replay_url])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "vulnerabilities": [],
            "claims": {},
            "alg": "",
        }
        for line in output.splitlines():
            l = line.strip()
            m = re.match(r"\[\+\]\s+(.*?)\s+vulnerab", l, re.IGNORECASE)
            if m:
                result["vulnerabilities"].append(m.group(1).strip())
                continue
            m = re.match(r"\[ALG\]\s*([A-Za-z0-9]+)", l)
            if m:
                result["alg"] = m.group(1)
                continue
            # Claim lines: "exp = 1234567890" / "sub = admin"
            m = re.match(r"^\[?\+?\]?\s*([a-zA-Z_]+)\s*=\s*(.+)$", l)
            if m and m.group(1) in {
                "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "kid", "alg"
            }:
                result["claims"][m.group(1)] = m.group(2).strip()
        return result

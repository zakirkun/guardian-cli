"""
Kerbrute wrapper — Kerberos user enumeration + password spray.

Sends AS-REQ to KDC; valid usernames return KRB_AS_REP_NEEDED, invalid
return KDC_ERR_C_PRINCIPAL_UNKNOWN. No event logs on the DC by default,
so it's quieter than SMB-based enum.

Risk class: ``intrusive``. Spray mode is destructive — may trigger
account lockout policy.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class KerbruteTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.tool_name = "kerbrute"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("kerbrute", {})
        action = kwargs.get("action", cfg.get("action", "userenum"))
        domain = kwargs.get("domain", cfg.get("domain", target))
        wordlist = kwargs.get("wordlist", cfg.get("wordlist", "users.txt"))

        cmd: List[str] = ["kerbrute", action, "-d", domain]
        cmd.append(wordlist)
        # Optional: ``passwordspray`` mode appends ``<password>`` literal.
        if action == "passwordspray":
            password = kwargs.get("password", cfg.get("password", ""))
            cmd.append(password)
        # Bound rate to be safer (default kerbrute is fast enough to lock
        # accounts).
        cmd.extend(["--threads", str(int(kwargs.get("threads", cfg.get("threads", 8))))])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "valid_users": [],
            "valid_creds": [],
            "lockout_risk": False,
        }
        for line in output.splitlines():
            # "[+] VALID USERNAME: alice@CORP.LOCAL"
            m = re.search(r"VALID USERNAME:\s*(\S+)", line)
            if m:
                result["valid_users"].append(m.group(1))
                continue
            # "[+] VALID LOGIN: alice@CORP.LOCAL:Password1"
            m = re.search(r"VALID LOGIN:\s*(\S+):(\S+)", line)
            if m:
                result["valid_creds"].append({
                    "user": m.group(1),
                    "password": "***",  # never echo plaintext
                })
            if "lockout" in line.lower():
                result["lockout_risk"] = True
        return result

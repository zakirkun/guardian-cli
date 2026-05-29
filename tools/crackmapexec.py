"""
NetExec / CrackMapExec wrapper — Active Directory swiss-army knife.

NetExec (``nxc``) is the actively-maintained CrackMapExec successor.
Supports SMB / WinRM / LDAP / SSH / MSSQL across Windows hosts.

Risk class: ``intrusive``. Operator must supply credentials and target
range; safe_mode in ``pentest`` config blocks destructive actions like
password-spray with high attempt counts.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from tools.base_tool import BaseTool


class CrackMapExecTool(BaseTool):
    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        # Modern binary is ``nxc``; fall back to legacy ``crackmapexec``.
        self.tool_name = "nxc"

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        cfg = self.config.get("tools", {}).get("crackmapexec", {})
        protocol = kwargs.get("protocol", cfg.get("protocol", "smb"))
        action = kwargs.get("action", cfg.get("action", "enum"))

        cmd: List[str] = ["nxc", protocol, target]

        username = kwargs.get("username", cfg.get("username"))
        password = kwargs.get("password", cfg.get("password"))
        nthash = kwargs.get("nthash", cfg.get("nthash"))
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        elif nthash:
            cmd.extend(["-H", nthash])

        # Action selectors (subset — common red-team checks).
        if action == "shares":
            cmd.append("--shares")
        elif action == "users":
            cmd.append("--users")
        elif action == "loggedon":
            cmd.append("--loggedon-users")
        elif action == "spray":
            # Password spray — destructive, gated by safe_mode in workflow.
            wordlist = kwargs.get("wordlist", cfg.get("wordlist"))
            if wordlist:
                cmd.extend(["-p", wordlist])
        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "hosts_responsive": [],
            "shares": [],
            "users": [],
            "creds_validated": [],
        }
        for line in output.splitlines():
            # Successful auth: "[+] DOMAIN\user:pass (Pwn3d!)"
            if "[+]" in line and "(" in line:
                m = re.search(
                    r"\[\+\]\s+(\S+)\s+\d+\s+(\S+)\s+(\S+):(\S+)",
                    line,
                )
                if m:
                    result["creds_validated"].append({
                        "host": m.group(1),
                        "fqdn": m.group(2),
                        "user": m.group(3),
                        "secret": "***",
                    })
            m = re.match(r"^(\S+)\s+\d+\s+\S+\s+\[\*\]\s+", line)
            if m:
                host = m.group(1)
                if host not in result["hosts_responsive"]:
                    result["hosts_responsive"].append(host)
            if "Permissions" in line and "Share" in line:
                continue  # header
            m = re.match(r"^\S+\s+\d+\s+\S+\s+(\S+)\s+(READ|WRITE|READ,WRITE)", line)
            if m:
                result["shares"].append({"name": m.group(1), "perms": m.group(2)})
        return result

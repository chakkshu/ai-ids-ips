"""Windows firewall adapter using ``netsh advfirewall``.

Commands are always argument lists passed to ``shell=False``. The adapter
builder is also used by the dry-run adapter to record exact command previews.
"""

from __future__ import annotations

import re
from typing import Any

from prevention.ip_blocker import (
    RULE_PREFIX,
    CommandResult,
    FirewallAdapter,
    execute_firewall_command,
    parse_ip,
)

_RULE_NAME_RE = re.compile(rf"{RULE_PREFIX}[0-9a-f]{{12}}")


class WindowsFirewallAdapter(FirewallAdapter):
    """Real Windows firewall adapter (only executable after safety checks)."""

    name = "windows-netsh"

    def __init__(self, executor: Any = None) -> None:
        self._executor = executor or execute_firewall_command

    def build_block_command(self, ip: str, rule_name: str) -> list[str]:
        address = str(parse_ip(ip))
        if not rule_name.startswith(RULE_PREFIX):
            raise ValueError("invalid firewall rule name")
        return [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={address}",
            "enable=yes",
        ]

    def build_unblock_command(self, ip: str, rule_name: str) -> list[str]:
        del ip
        if not rule_name.startswith(RULE_PREFIX):
            raise ValueError("invalid firewall rule name")
        return [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

    def build_list_command(self) -> list[str]:
        return [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={RULE_PREFIX}*",
        ]

    def block(self, ip: str, duration_minutes: int) -> CommandResult:
        del duration_minutes
        command = self.build_block_command(ip, self.rule_name(ip))
        return self._executor(command)

    def unblock(self, ip: str) -> CommandResult:
        command = self.build_unblock_command(ip, self.rule_name(ip))
        return self._executor(command)

    def list_rules(self) -> list[str]:
        result = self._executor(self.build_list_command())
        if not result.success:
            return []
        return sorted(set(_RULE_NAME_RE.findall(result.stdout)))

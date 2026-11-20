"""Linux firewall adapter using iptables/ip6tables.

Rules are idempotent through a comment marker derived from the validated IP.
Every command is an argument list executed with ``shell=False``.
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


class LinuxFirewallAdapter(FirewallAdapter):
    """Real Linux firewall adapter (only executable after safety checks)."""

    name = "linux-iptables"

    def __init__(self, executor: Any = None) -> None:
        self._executor = executor or execute_firewall_command

    @staticmethod
    def _executable(ip: str) -> str:
        return "ip6tables" if parse_ip(ip).version == 6 else "iptables"

    def _rule_args(self, ip: str, rule_name: str) -> list[str]:
        if not rule_name.startswith(RULE_PREFIX):
            raise ValueError("invalid firewall rule name")
        return [
            "-s",
            str(parse_ip(ip)),
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            rule_name,
        ]

    def build_block_command(self, ip: str, rule_name: str) -> list[str]:
        return [
            self._executable(ip),
            "-I",
            "INPUT",
            *self._rule_args(ip, rule_name),
        ]

    def build_check_command(self, ip: str, rule_name: str) -> list[str]:
        return [
            self._executable(ip),
            "-C",
            "INPUT",
            *self._rule_args(ip, rule_name),
        ]

    def build_unblock_command(self, ip: str, rule_name: str) -> list[str]:
        return [
            self._executable(ip),
            "-D",
            "INPUT",
            *self._rule_args(ip, rule_name),
        ]

    def build_list_command(self) -> list[str]:
        return ["iptables", "-S", "INPUT"]

    def block(self, ip: str, duration_minutes: int) -> CommandResult:
        del duration_minutes
        rule_name = self.rule_name(ip)
        existing = self._executor(self.build_check_command(ip, rule_name))
        if existing.success:
            return CommandResult(
                success=True,
                dry_run=False,
                preview="[]",
                stdout="rule already present",
            )
        result = self._executor(self.build_block_command(ip, rule_name))
        if not result.success and "no chain" in result.stderr.lower():
            return CommandResult(
                success=False,
                dry_run=False,
                preview=result.preview,
                stderr=result.stderr,
                error="iptables INPUT chain is unavailable",
            )
        return result

    def unblock(self, ip: str) -> CommandResult:
        rule_name = self.rule_name(ip)
        existing = self._executor(self.build_check_command(ip, rule_name))
        if not existing.success:
            return CommandResult(
                success=True,
                dry_run=False,
                preview="[]",
                stdout="rule already absent",
            )
        return self._executor(self.build_unblock_command(ip, rule_name))

    def list_rules(self) -> list[str]:
        result = self._executor(self.build_list_command())
        if not result.success:
            return []
        return sorted(set(_RULE_NAME_RE.findall(result.stdout)))

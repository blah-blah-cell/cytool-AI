"""Bounded local terminal context and execution.

No shell is invoked. Commands are parsed into argv and must match a small,
read-only allowlist. This is intentionally a control plane, not an arbitrary
agent shell.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .approval import ApprovalMode

SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)
METACHARACTERS = set("|;&><`$()")
SAFE_COMMANDS = {
    "pwd": {()},
    "ls": {(), ("-la",), ("-l",), ("-a",)},
    "git": {("status",), ("status", "--short"), ("diff",), ("diff", "--stat"), ("log", "-1", "--oneline")},
    "rg": {( "--files",)},
}


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    mode: str
    executed: bool
    returncode: int | None
    stdout: str
    stderr: str


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def parse_safe(command: str) -> tuple[str, ...]:
    if any(character in command for character in METACHARACTERS):
        raise PermissionError("shell syntax, redirects, substitutions, and command chaining are not allowed")
    parts = tuple(shlex.split(command))
    if not parts or parts[0] not in SAFE_COMMANDS or parts[1:] not in SAFE_COMMANDS[parts[0]]:
        raise PermissionError("command is not in the local read-only allowlist")
    return parts


def execute(command: str, mode: ApprovalMode, cwd: Path) -> CommandResult:
    argv = parse_safe(command)
    if mode is not ApprovalMode.APPROVED:
        return CommandResult(argv, str(mode), False, None, "", "execution requires --mode approved")
    executed_argv = argv
    if argv[0] == "git":
        executed_argv = ("git", "-c", "core.fsmonitor=false", "-c", "diff.external=", *argv[1:])
    completed = subprocess.run(
        executed_argv,
        cwd=cwd,
        env={
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_EXTERNAL_DIFF": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
        },
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    return CommandResult(argv, str(mode), True, completed.returncode, redact(completed.stdout), redact(completed.stderr))


def terminal_snapshot(cwd: Path) -> dict[str, object]:
    """Gather a tiny, non-secret local context from the supplied directory."""
    entries = []
    for command in ("pwd", "git status --short", "git diff --stat"):
        result = execute(command, ApprovalMode.APPROVED, cwd)
        entries.append(asdict(result))
    return {"cwd": str(cwd.resolve()), "commands": entries}

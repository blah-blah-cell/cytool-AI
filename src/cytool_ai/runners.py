"""Runner profiles for future isolated/local or remote execution.

Profiles are descriptive only in v0.1. They do not start containers, SSH
sessions, agents, or external processes.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunnerProfile:
    id: str
    kind: str
    network: str
    description: str


DEFAULTS = (
    RunnerProfile("local-evidence", "local", "disabled", "Read-only local evidence workflow."),
    RunnerProfile("container-evidence", "container", "disabled", "Planned isolated evidence worker; not yet provisioned."),
    RunnerProfile("remote-evidence", "remote", "disabled", "Planned operator-managed remote worker; not yet provisioned."),
)


def list_profiles() -> list[dict[str, str]]:
    return [asdict(profile) for profile in DEFAULTS]

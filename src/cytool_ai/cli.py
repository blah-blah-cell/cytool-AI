"""Command line interface for cytool-AI."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from . import __version__
from .audit import read, record
from .modules import install, installed, registry
from .workspaces import create, open_workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cytool", description="cytool-AI: authorized security research automation")
    parser.add_argument("--version", action="version", version=f"cytool-AI {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a local research workspace")
    init.add_argument("name")

    modules = commands.add_parser("modules", help="discover and install capability modules")
    module_commands = modules.add_subparsers(dest="module_command", required=True)
    module_commands.add_parser("list", help="list available modules")
    module_install = module_commands.add_parser("install", help="install a module into a workspace")
    module_install.add_argument("module_id")
    module_install.add_argument("--workspace", required=True)

    run = commands.add_parser("run", help="record an authorized module execution request")
    run.add_argument("module_id")
    run.add_argument("--workspace", required=True)
    run.add_argument("--authorized", action="store_true", help="confirm you are authorized to use this module")

    audit = commands.add_parser("audit", help="show workspace audit events")
    audit.add_argument("--workspace", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            path = create(args.name)
            print(f"Created workspace: {path}")
            return 0
        if args.command == "modules" and args.module_command == "list":
            for module in registry().values():
                flag = "authorization required" if module.requires_authorization else "offline/local"
                print(f"{module.id:<24} {module.category:<18} {flag}\n  {module.summary}")
            return 0
        if args.command == "modules":
            workspace = open_workspace(args.workspace)
            module = install(workspace, args.module_id)
            record(workspace, "module.installed", module_id=module.id, version=module.version)
            print(f"Installed {module.id} in {args.workspace}")
            return 0
        if args.command == "run":
            workspace = open_workspace(args.workspace)
            module = installed(workspace).get(args.module_id)
            if module is None:
                raise RuntimeError(f"module is not installed: {args.module_id}")
            if module["requires_authorization"] and not args.authorized:
                raise PermissionError("this module requires --authorized confirmation")
            record(workspace, "module.execution_requested", module_id=args.module_id, authorized=args.authorized)
            print(f"Recorded execution request for {args.module_id}. No active operation was performed.")
            return 0
        if args.command == "audit":
            events = read(open_workspace(args.workspace))
            print(json.dumps(events, indent=2))
            return 0
    except (FileExistsError, FileNotFoundError, KeyError, PermissionError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Command line interface for cytool-AI."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .ai import build_context, chat, configure, response_text
from .approval import ApprovalMode, description
from .audit import read, record
from .analysis import inspect_file
from .dashboard import serve
from .modules import install, installed, registry
from .policy import Scope, save, validate_target
from .reports import write_ai_bundle, write_report
from .terminal import execute
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

    scope = commands.add_parser("scope", help="declare and validate authorized assessment scope")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    scope_set = scope_commands.add_parser("set", help="save explicit authorization and approved domains")
    scope_set.add_argument("--workspace", required=True)
    scope_set.add_argument("--engagement", required=True)
    scope_set.add_argument("--authorized-by", required=True)
    scope_set.add_argument("--domain", action="append", required=True)
    scope_check = scope_commands.add_parser("check", help="confirm a target falls inside declared scope")
    scope_check.add_argument("target")
    scope_check.add_argument("--workspace", required=True)

    run = commands.add_parser("run", help="record an authorized module execution request")
    run.add_argument("module_id")
    run.add_argument("--workspace", required=True)
    run.add_argument("--authorized", action="store_true", help="confirm you are authorized to use this module")
    run.add_argument("--target", help="optional target; validated against declared scope")

    inspect = commands.add_parser("inspect", help="analyze supplied evidence without executing it")
    inspect.add_argument("path")
    inspect.add_argument("--workspace", required=True)
    inspect.add_argument("--module", default="artifact-inspector")
    inspect.add_argument("--ai-bundle", action="store_true", help="write a local provider-neutral AI evidence bundle")

    report = commands.add_parser("report", help="make a Markdown report from an evidence JSON file")
    report.add_argument("evidence_json")
    report.add_argument("--title", default="cytool-AI evidence report")
    report.add_argument("--workspace", required=True)

    dashboard = commands.add_parser("dashboard", help="run a local dashboard JSON API")
    dashboard.add_argument("--workspace", required=True)
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8765)

    terminal = commands.add_parser("terminal", help="preview or run a policy-allowed local command")
    terminal.add_argument("terminal_command")
    terminal.add_argument("--workspace", required=True)
    terminal.add_argument("--mode", choices=[mode.value for mode in ApprovalMode], default=ApprovalMode.PLAN.value)
    terminal.add_argument("--cwd", default=".", help="directory in which to run the command")

    ai = commands.add_parser("ai", help="OpenAI-compatible assistant workflows")
    ai_commands = ai.add_subparsers(dest="ai_command", required=True)
    ai_configure = ai_commands.add_parser("configure", help="store an OpenAI-compatible provider configuration")
    ai_configure.add_argument("--base-url", required=True, help="for example https://api.openai.com/v1")
    ai_configure.add_argument("--model", required=True)
    ai_configure.add_argument("--api-key-env", default="OPENAI_API_KEY")
    for name, help_text in (("ask", "ask a security research question"), ("teach", "request a tutorial from current context"), ("fix", "request a reviewable remediation plan")):
        assistant_command = ai_commands.add_parser(name, help=help_text)
        assistant_command.add_argument("prompt")
        assistant_command.add_argument("--workspace")
        assistant_command.add_argument("--terminal-context", action="store_true")
        assistant_command.add_argument("--cwd", default=".")

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
        if args.command == "scope" and args.scope_command == "set":
            workspace = open_workspace(args.workspace)
            domains = tuple(domain.lower().strip().rstrip(".") for domain in args.domain)
            save(workspace, Scope(args.engagement, args.authorized_by, domains))
            record(workspace, "scope.declared", engagement=args.engagement, domains=domains)
            print(f"Declared scope for {args.workspace}: {', '.join(domains)}")
            return 0
        if args.command == "scope":
            host = validate_target(open_workspace(args.workspace), args.target)
            print(f"In scope: {host}")
            return 0
        if args.command == "run":
            workspace = open_workspace(args.workspace)
            module = installed(workspace).get(args.module_id)
            if module is None:
                raise RuntimeError(f"module is not installed: {args.module_id}")
            if module["requires_authorization"] and not args.authorized:
                raise PermissionError("this module requires --authorized confirmation")
            target = validate_target(workspace, args.target) if args.target else None
            record(workspace, "module.execution_requested", module_id=args.module_id, authorized=args.authorized, target=target)
            print(f"Recorded execution request for {args.module_id}. No active operation was performed.")
            return 0
        if args.command == "inspect":
            workspace = open_workspace(args.workspace)
            if args.module not in installed(workspace):
                raise RuntimeError(f"module is not installed: {args.module}")
            evidence = inspect_file(Path(args.path))
            report_path = write_report(workspace, f"{args.module}: evidence inspection", evidence)
            if args.ai_bundle:
                bundle_path = write_ai_bundle(workspace, "Summarize and prioritize supplied offline evidence.", evidence)
                print(f"AI evidence bundle: {bundle_path}")
            record(workspace, "evidence.inspected", module_id=args.module, sha256=evidence["sha256"])
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
        if args.command == "report":
            workspace = open_workspace(args.workspace)
            evidence = json.loads(Path(args.evidence_json).read_text(encoding="utf-8"))
            report_path = write_report(workspace, args.title, evidence)
            record(workspace, "report.created", report=str(report_path))
            print(report_path)
            return 0
        if args.command == "dashboard":
            serve(args.workspace, args.host, args.port)
            return 0
        if args.command == "terminal":
            workspace = open_workspace(args.workspace)
            mode = ApprovalMode(args.mode)
            result = execute(args.terminal_command, mode, Path(args.cwd))
            record(workspace, "terminal.command", command=list(result.command), mode=result.mode, executed=result.executed, returncode=result.returncode)
            print(json.dumps({"authorization": description(mode), **result.__dict__}, indent=2))
            return 0 if result.returncode in {None, 0} else result.returncode
        if args.command == "ai" and args.ai_command == "configure":
            settings = configure(args.base_url, args.model, args.api_key_env)
            print(f"Configured {settings.base_url} with model {settings.model}; key remains in ${settings.api_key_env}.")
            return 0
        if args.command == "ai":
            workspace = open_workspace(args.workspace) if args.workspace else None
            context = build_context(workspace, args.terminal_context, Path(args.cwd))
            prefixes = {
                "teach": "Teach this clearly, using the supplied context and emphasizing safe, authorized practice:\n",
                "fix": "Analyze this and propose a reviewable remediation plan. Do not execute commands:\n",
                "ask": "Answer this with practical, authorization-first guidance:\n",
            }
            response = chat([{"role": "user", "content": prefixes[args.ai_command] + args.prompt}], context=context)
            if workspace:
                record(workspace, "ai.request", workflow=args.ai_command, terminal_context=args.terminal_context)
            print(response_text(response))
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

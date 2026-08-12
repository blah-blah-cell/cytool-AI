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
from .findings import add as add_finding
from .findings import list_all
from .investigations import binary_metadata, cloud_export_review, memory_artifact_scan, web_evidence, web_input_surface
from .integrations import discover
from .runners import list_profiles
from .operations import backup, doctor
from .exports import write_sarif, write_stix
from .retools import inspect as external_re_inspect
from .iocs import extract as extract_iocs
from .iocs import list_all as list_iocs
from .dfirtools import volatility, yara_scan
from .modules import install, installed, registry
from .policy import Scope, save, validate_target
from .reports import write_ai_bundle, write_report
from .terminal import execute
from .toolpacks import fetch as fetch_toolpack
from .toolpacks import register as register_toolpack
from .toolpacks import registered as registered_toolpacks
from .logs import correlate
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

    toolpacks = commands.add_parser("toolpacks", help="register and fetch integrity-verified, non-executable tool packs")
    toolpack_commands = toolpacks.add_subparsers(dest="toolpack_command", required=True)
    toolpack_list = toolpack_commands.add_parser("list", help="list registered tool packs")
    toolpack_list.add_argument("--workspace", required=True)
    toolpack_register = toolpack_commands.add_parser("register", help="register a local JSON tool-pack manifest")
    toolpack_register.add_argument("manifest")
    toolpack_register.add_argument("--workspace", required=True)
    toolpack_fetch = toolpack_commands.add_parser("fetch", help="download a registered pack and verify SHA-256")
    toolpack_fetch.add_argument("pack_id")
    toolpack_fetch.add_argument("--workspace", required=True)

    logs = commands.add_parser("logs", help="offline analysis of supplied text logs")
    log_commands = logs.add_subparsers(dest="log_command", required=True)
    log_correlate = log_commands.add_parser("correlate", help="merge and order timestamped log lines")
    log_correlate.add_argument("paths", nargs="+")
    log_correlate.add_argument("--workspace", required=True)

    binary = commands.add_parser("binary", help="offline binary and reverse-engineering metadata")
    binary_commands = binary.add_subparsers(dest="binary_command", required=True)
    binary_inspect = binary_commands.add_parser("inspect", help="parse ELF/PE container metadata without execution")
    binary_inspect.add_argument("path")
    binary_inspect.add_argument("--workspace", required=True)
    binary_external = binary_commands.add_parser("external", help="capture metadata from an installed RE utility")
    binary_external.add_argument("tool", choices=["readelf", "objdump", "rabin2"])
    binary_external.add_argument("path")
    binary_external.add_argument("--workspace", required=True)

    memory = commands.add_parser("memory", help="offline analysis of supplied memory captures")
    memory_commands = memory.add_subparsers(dest="memory_command", required=True)
    memory_scan = memory_commands.add_parser("scan", help="extract URLs and IP evidence from a capture")
    memory_scan.add_argument("path")
    memory_scan.add_argument("--workspace", required=True)
    memory_scan.add_argument("--authorized", action="store_true")
    memory_scan.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)

    web = commands.add_parser("web", help="scope-constrained web evidence review")
    web_commands = web.add_subparsers(dest="web_command", required=True)
    web_headers = web_commands.add_parser("headers", help="collect HTTP response headers; no payloads or crawling")
    web_headers.add_argument("url")
    web_headers.add_argument("--workspace", required=True)
    web_headers.add_argument("--authorized", action="store_true")
    web_forms = web_commands.add_parser("forms", help="inventory HTML forms and scripts; no payload injection")
    web_forms.add_argument("url")
    web_forms.add_argument("--workspace", required=True)
    web_forms.add_argument("--authorized", action="store_true")

    cloud = commands.add_parser("cloud", help="offline review of exported cloud configuration")
    cloud_commands = cloud.add_subparsers(dest="cloud_command", required=True)
    cloud_review = cloud_commands.add_parser("review", help="identify baseline posture flags in a JSON export")
    cloud_review.add_argument("path")
    cloud_review.add_argument("--workspace", required=True)
    cloud_review.add_argument("--authorized", action="store_true")

    findings = commands.add_parser("findings", help="list generated case findings")
    findings.add_argument("--workspace", required=True)

    export = commands.add_parser("export", help="export case findings for downstream tools")
    export_commands = export.add_subparsers(dest="export_command", required=True)
    export_sarif = export_commands.add_parser("sarif", help="write SARIF 2.1.0 findings")
    export_sarif.add_argument("--workspace", required=True)
    export_sarif.add_argument("--output", required=True)
    export_stix = export_commands.add_parser("stix", help="write STIX 2.1 indicators")
    export_stix.add_argument("--workspace", required=True)
    export_stix.add_argument("--output", required=True)

    iocs = commands.add_parser("iocs", help="extract and manage local indicators")
    ioc_commands = iocs.add_subparsers(dest="ioc_command", required=True)
    ioc_extract = ioc_commands.add_parser("extract", help="extract indicators from a supplied text or binary file")
    ioc_extract.add_argument("path")
    ioc_extract.add_argument("--workspace", required=True)
    ioc_list = ioc_commands.add_parser("list", help="list deduplicated workspace indicators")
    ioc_list.add_argument("--workspace", required=True)

    dfir = commands.add_parser("dfir", help="optional offline YARA and Volatility adapters")
    dfir_commands = dfir.add_subparsers(dest="dfir_command", required=True)
    yara = dfir_commands.add_parser("yara", help="scan a supplied file using local YARA rules")
    yara.add_argument("rules")
    yara.add_argument("target")
    yara.add_argument("--workspace", required=True)
    yara.add_argument("--authorized", action="store_true")
    vol = dfir_commands.add_parser("volatility", help="run an allowlisted Volatility plugin on a supplied capture")
    vol.add_argument("image")
    vol.add_argument("plugin")
    vol.add_argument("--workspace", required=True)
    vol.add_argument("--authorized", action="store_true")

    integrations = commands.add_parser("integrations", help="discover optional locally installed analysis tools")
    integrations.add_argument("action", choices=["list"], nargs="?", default="list")
    runners = commands.add_parser("runners", help="show execution-isolation profiles")
    runners.add_argument("action", choices=["list"], nargs="?", default="list")

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

    doctor_command = commands.add_parser("doctor", help="check cytool-AI provider, workspace, and local integration readiness")
    doctor_command.add_argument("--workspace")
    backup_command = commands.add_parser("backup", help="create a portable ZIP backup of a workspace")
    backup_command.add_argument("--workspace", required=True)
    backup_command.add_argument("--output", required=True)
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
            add_finding(workspace, f"{args.module}: evidence inspection", report_path)
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
            add_finding(workspace, args.title, report_path)
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
        if args.command == "toolpacks" and args.toolpack_command == "list":
            packs = registered_toolpacks(open_workspace(args.workspace))
            print(json.dumps({pack_id: pack.__dict__ for pack_id, pack in packs.items()}, indent=2))
            return 0
        if args.command == "toolpacks" and args.toolpack_command == "register":
            workspace = open_workspace(args.workspace)
            pack = register_toolpack(workspace, Path(args.manifest))
            record(workspace, "toolpack.registered", pack_id=pack.id, version=pack.version)
            print(f"Registered {pack.id} ({pack.version}); it has not been downloaded or executed.")
            return 0
        if args.command == "toolpacks":
            workspace = open_workspace(args.workspace)
            archive = fetch_toolpack(workspace, args.pack_id)
            record(workspace, "toolpack.fetched", pack_id=args.pack_id, archive=str(archive))
            print(f"Verified download saved to {archive}. It has not been executed.")
            return 0
        if args.command == "logs":
            workspace = open_workspace(args.workspace)
            if "log-correlation" not in installed(workspace):
                raise RuntimeError("module is not installed: log-correlation")
            evidence = correlate([Path(path) for path in args.paths])
            report_path = write_report(workspace, "Log correlation", evidence)
            add_finding(workspace, "Log correlation", report_path)
            record(workspace, "logs.correlated", sources=evidence["sources"], event_count=evidence["event_count"])
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
        if args.command == "binary":
            workspace = open_workspace(args.workspace)
            if "binary-fingerprint" not in installed(workspace):
                raise RuntimeError("module is not installed: binary-fingerprint")
            evidence = binary_metadata(Path(args.path)) if args.binary_command == "inspect" else external_re_inspect(Path(args.path), args.tool)
            title = "Binary metadata" if args.binary_command == "inspect" else f"External RE evidence ({args.tool})"
            report_path = write_report(workspace, title, evidence)
            add_finding(workspace, title, report_path)
            record(workspace, "binary.inspected", path=str(Path(args.path).resolve()), engine=args.binary_command)
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
        if args.command == "memory":
            workspace = open_workspace(args.workspace)
            if "memory-artifact-triage" not in installed(workspace):
                raise RuntimeError("module is not installed: memory-artifact-triage")
            if not args.authorized:
                raise PermissionError("memory analysis requires --authorized confirmation")
            if not 1 <= args.max_bytes <= 512 * 1024 * 1024:
                raise ValueError("max-bytes must be between 1 and 536870912")
            evidence = memory_artifact_scan(Path(args.path), max_bytes=args.max_bytes)
            report_path = write_report(workspace, "Memory artifact triage", evidence)
            add_finding(workspace, "Memory artifact triage", report_path, "medium" if evidence["urls"] else "info")
            record(workspace, "memory.scanned", path=evidence["path"], bytes_examined=evidence["bytes_examined"])
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
        if args.command == "web":
            workspace = open_workspace(args.workspace)
            if "web-scope-check" not in installed(workspace):
                raise RuntimeError("module is not installed: web-scope-check")
            if not args.authorized:
                raise PermissionError("web evidence review requires --authorized confirmation")
            validate_target(workspace, args.url)
            evidence = web_evidence(args.url) if args.web_command == "headers" else web_input_surface(args.url)
            title = "Web response-header review" if args.web_command == "headers" else "Web input-surface inventory"
            severity = "low" if args.web_command == "headers" and evidence["missing_recommended_headers"] else "info"
            report_path = write_report(workspace, title, evidence)
            add_finding(workspace, title, report_path, severity)
            record(workspace, f"web.{args.web_command}_reviewed", url=args.url, status=evidence["status"])
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
        if args.command == "cloud":
            workspace = open_workspace(args.workspace)
            if "cloud-evidence-review" not in installed(workspace):
                raise RuntimeError("module is not installed: cloud-evidence-review")
            if not args.authorized:
                raise PermissionError("cloud evidence review requires --authorized confirmation")
            evidence = cloud_export_review(Path(args.path))
            report_path = write_report(workspace, "Cloud export posture review", evidence)
            add_finding(workspace, "Cloud export posture review", report_path, "medium" if evidence["findings"] else "info")
            record(workspace, "cloud.export_reviewed", path=evidence["path"], finding_count=evidence["finding_count"])
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
        if args.command == "findings":
            print(json.dumps(list_all(open_workspace(args.workspace)), indent=2))
            return 0
        if args.command == "integrations":
            print(json.dumps(discover(), indent=2))
            return 0
        if args.command == "runners":
            print(json.dumps(list_profiles(), indent=2))
            return 0
        if args.command == "export":
            workspace = open_workspace(args.workspace)
            output = write_sarif(workspace, Path(args.output)) if args.export_command == "sarif" else write_stix(workspace, Path(args.output))
            record(workspace, "findings.exported", format=args.export_command, output=str(output))
            print(output)
            return 0
        if args.command == "iocs" and args.ioc_command == "extract":
            workspace = open_workspace(args.workspace)
            indicators = extract_iocs(workspace, Path(args.path))
            record(workspace, "iocs.extracted", source=str(Path(args.path).resolve()), count=len(indicators))
            print(json.dumps(indicators, indent=2))
            return 0
        if args.command == "iocs":
            print(json.dumps(list_iocs(open_workspace(args.workspace)), indent=2))
            return 0
        if args.command == "dfir":
            workspace = open_workspace(args.workspace)
            if not args.authorized:
                raise PermissionError("DFIR tool adapters require --authorized confirmation")
            evidence = yara_scan(Path(args.rules), Path(args.target)) if args.dfir_command == "yara" else volatility(Path(args.image), args.plugin)
            title = "YARA evidence" if args.dfir_command == "yara" else "Volatility evidence"
            report_path = write_report(workspace, title, evidence)
            add_finding(workspace, title, report_path)
            record(workspace, f"dfir.{args.dfir_command}", returncode=evidence["returncode"])
            print(json.dumps({"evidence": evidence, "report": str(report_path)}, indent=2))
            return 0
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
        if args.command == "doctor":
            workspace = open_workspace(args.workspace) if args.workspace else None
            print(json.dumps(doctor(workspace), indent=2))
            return 0
        if args.command == "backup":
            workspace = open_workspace(args.workspace)
            output = backup(workspace, Path(args.output))
            record(workspace, "workspace.backed_up", output=str(output))
            print(output)
            return 0
    except (FileExistsError, FileNotFoundError, KeyError, PermissionError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

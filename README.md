# cytool-AI

CyTool AI is a Linux tool for authorized security research and defensive work.
Use it to open a case, inspect evidence, and review findings in a local
dashboard. AI assistance is optional.

Version 2.0 includes tests for the CLI, pipelines, and dashboard API.

## How it handles case data

Workspaces, evidence, reports, and audit logs stay on your machine by default.
Protected modules require `--authorized`, and web checks must match a declared
domain scope. The append-only JSON Lines log records installations, analysis
actions, AI requests, and terminal requests.

Install the modules you need. Tool packs require a manifest and SHA-256
verification. CyTool stores downloaded packs without running them. If you
connect an OpenAI-compatible provider, it reads the API key from an
environment variable.

## What works today

| Area | Current capability | Boundary |
| --- | --- | --- |
| Case management | Workspaces, reports, findings, audit history, SARIF export | Local files only |
| Artifact triage | Streaming full-file hashes, bounded string sampling, format hints | Supplied files are never executed |
| RE | ELF/PE metadata, hashes, entropy windows, explainable capability indicators, and optional `readelf`/`objdump`/`rabin2` evidence | Static indicators are not a malware verdict |
| Memory | Chunk-streamed URL, IP, domain, email, path, and SHA-256 evidence up to 512 MiB | Capture is read, never executed |
| DFIR tools | Optional local YARA and Volatility adapters | Explicit authorization and user-supplied rules/images |
| Logs | Streaming timestamp correlation across up to 128 MiB of text logs | Offline only |
| IOCs | Local extraction (first 64 MiB), full-file hash, index, and STIX 2.1 export | No automatic external enrichment |
| Cloud | Baseline posture flags in supplied JSON exports up to 32 MiB | Offline only |
| Web | Response headers, HTML form/script inventory, and TLS certificate/protocol evidence | One in-scope request or handshake; no crawling or payload injection |
| Pipelines | Validated JSON automation across artifact, binary, memory, cloud, IOC, and log workflows | Bundled dispatch only; no shell or manifest code loading |
| AI | `ask`, `teach`, and review-only `fix` grounded in bounded case reports, IOCs, scope, modules, runs, and audit history | Explicit provider configuration and opt-in terminal context |
| Terminal | `plan`, `confirm`, and `approved` modes | Tiny read-only argv allowlist; no shell/network/privilege escalation |

## Install

Python 3.11 or later is required.

```bash
git clone https://github.com/blah-blah-cell/cytool-AI.git
cd cytool-AI
python3 -m pip install -e .
```

## Five-minute start

```bash
# Create a case workspace.
cytool init research-lab

# Triage a file locally.
cytool modules install artifact-inspector --workspace research-lab
cytool inspect ./suspicious-file --workspace research-lab --ai-bundle

# Review the local case dashboard.
cytool dashboard --workspace research-lab
# Open http://127.0.0.1:8765/
```

By default, workspaces are stored in `~/.local/share/cytool-ai/workspaces`.
Set `CYTOOL_HOME` to use another parent directory.

## Dashboard workflows

Use the dashboard to install modules or upload a file for static inspection.
It can run binary, memory, cloud, and IOC checks on uploaded artifacts, save
and run a pipeline, and correlate logs. It also supports scoped passive HTTP
and TLS checks, optional local reverse-engineering tools, and SARIF or STIX
exports.

Each action uses the same module and authorization checks as the CLI, writes an
audit event, and generates a local report/finding where applicable. The AI panel
stores provider configuration without an API key; export the key in the shell
that starts the dashboard before making an AI request.

## Typical workflows

### Binary and reverse-engineering evidence

```bash
cytool modules install binary-fingerprint --workspace research-lab
cytool binary inspect ./sample.bin --workspace research-lab
cytool integrations list
cytool binary external readelf ./sample.elf --workspace research-lab
```

### Memory and log evidence

```bash
cytool modules install memory-artifact-triage --workspace research-lab
cytool memory scan ./capture.raw --workspace research-lab --authorized

cytool modules install log-correlation --workspace research-lab
cytool logs correlate ./auth.log ./web.log --workspace research-lab
cytool iocs extract ./capture.raw --workspace research-lab
cytool export stix --workspace research-lab --output ./indicators.stix.json
```

### Declarative automation pipelines

A pipeline is a JSON list of steps. Each step runs a bundled workflow and
writes a report, finding, and audit event. The manifest cannot load plugins
or run shell code.

```json
{
  "name": "Artifact triage",
  "steps": [
    {"id": "hash", "workflow": "inspect", "path": "sample.bin"},
    {"id": "profile", "workflow": "binary", "path": "sample.bin"},
    {"id": "indicators", "workflow": "ioc", "path": "sample.bin"}
  ]
}
```

```bash
cytool pipeline run ./pipeline.json --workspace research-lab
cytool pipeline history --workspace research-lab
```

Protected `memory` and `cloud` steps require `--authorized`. Relative inputs
resolve from the manifest directory; dashboard pipelines are restricted to
already uploaded workspace artifacts.

### Authorized web and cloud review

```bash
cytool scope set --workspace research-lab \
  --engagement "Client review" --authorized-by client --domain example.com
cytool modules install web-scope-check --workspace research-lab
cytool web headers https://example.com --workspace research-lab --authorized
cytool web forms https://example.com/login --workspace research-lab --authorized
cytool web tls https://example.com --workspace research-lab --authorized

cytool modules install cloud-evidence-review --workspace research-lab
cytool cloud review ./cloud-export.json --workspace research-lab --authorized
```

### Optional YARA and Volatility

Install these tools through your operating system, then run them only against
data you are authorized to analyze:

```bash
cytool dfir yara ./rules.yar ./sample.bin --workspace research-lab --authorized
cytool dfir volatility ./capture.raw windows.pslist --workspace research-lab --authorized
```

### Reports and downstream export

```bash
cytool findings --workspace research-lab
cytool export sarif --workspace research-lab --output ./findings.sarif
```

## AI assistant

CyTool accepts OpenAI-compatible Chat Completions providers. It stores the
provider URL, the model, and the name of the environment variable that holds
the API key. It does not store the key itself.

```bash
export OPENAI_API_KEY="..."
export CYTOOL_SERVER_KEY="local-server-secret"

cytool ai configure --base-url https://api.openai.com/v1 \
  --model gpt-5 --api-key-env OPENAI_API_KEY
cytool ai teach "Explain the latest binary report" --workspace research-lab
cytool ai fix "Prioritize these case findings" --workspace research-lab
```

Workspace AI requests automatically include bounded recent reports, findings,
IOCs, scope, installed modules, pipeline runs, and audit events. Add
`--terminal-context` only when you also want to share a redacted snapshot of
`pwd`, `git status --short`, and `git diff --stat` from a chosen directory.

The local dashboard also serves `GET /v1/models` and authenticated
`POST /v1/chat/completions` for compatible local clients. It uses the same
bounded case grounding; clients may explicitly add
`"cytool_terminal_context": true` to opt into the redacted terminal snapshot.
The endpoint is localhost-only.

## Tool packs

A tool pack manifest must provide exactly `id`, `name`, `summary`, `version`,
`source`, and `sha256`. Sources must use HTTPS (or `file://` for local
development). Downloaded packs are checksum-verified and stored, **not run**.

```bash
cytool toolpacks register ./my-toolpack.json --workspace research-lab
cytool toolpacks fetch my-toolpack --workspace research-lab
```

## Safety model

Use cytool-AI only against systems, networks, and data you own or are
explicitly authorized to assess. Current web workflows avoid payload injection;
the terminal feature does not use a shell and rejects redirects, pipes,
substitutions, downloads, network commands, and privilege escalation. cytool-AI
does not advertise remote agents or container orchestration that it does not
implement.

## Development

```bash
PYTHONPATH=src python3 -m pytest
bash scripts/smoke-test.sh
python3 -m pip wheel --no-deps . -w dist
```

Every push and pull request runs this same test, smoke-test, and wheel-build
sequence through GitHub Actions.

## Operations

Run a readiness check to see the configured AI provider, installed workspace
modules, and optional local DFIR/RE integration availability:

```bash
cytool doctor --workspace research-lab
```

To move a case to another approved machine or retain its records, make a ZIP
backup. It includes evidence, reports, the audit log, and local indexes:

```bash
cytool backup --workspace research-lab --output ./research-lab-backup.zip
```

The project is MIT licensed, except for the explicitly attributed
Apache-2.0-derived approval utility documented in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

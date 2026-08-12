# cytool-AI

cytool-AI is a Linux-first, local-first cybersecurity automation workspace for
**authorized research and defensive operations**. It combines evidence
collection, case management, a local dashboard, optional AI assistance, and
integrity-verified tool packs without silently executing downloaded code.

> Status: v0.2 beta. The core control plane and initial evidence workflows are
> implemented. See [What works today](#what-works-today) for the exact scope.

## Why cytool-AI

- **Local by default** — workspaces, evidence, reports, and audit logs remain
  on the operator's machine.
- **Authorization first** — protected modules require `--authorized`; web work
  must match a declared domain scope.
- **Auditable** — installations, analysis actions, AI requests, and terminal
  requests are captured in an append-only JSON Lines audit trail.
- **Modular** — install only the capabilities you need. Tool packs require an
  explicit manifest and SHA-256 verification before download.
- **AI-ready, not AI-dependent** — connect an OpenAI-compatible provider when
  wanted; provider credentials are only read from an environment variable.

## What works today

| Area | Current capability | Boundary |
| --- | --- | --- |
| Case management | Workspaces, reports, findings, audit history, SARIF export | Local files only |
| Artifact triage | Hashes, strings, format hints | Supplied files are never executed |
| RE | Native ELF/PE metadata and optional `readelf`/`objdump`/`rabin2` evidence | Read-only parsers |
| Memory | Offline URL, IPv4, and domain extraction | Capture is read, never executed |
| DFIR tools | Optional local YARA and Volatility adapters | Explicit authorization and user-supplied rules/images |
| Logs | Timestamp correlation across text logs | Offline only |
| IOCs | Local extraction, index, and STIX 2.1 export | No automatic external enrichment |
| Cloud | Baseline posture flags in supplied JSON exports | Offline only |
| Web | Response-header review and HTML form/script inventory | One in-scope request; no crawling or payload injection |
| AI | `ask`, `teach`, and review-only `fix` workflows | Explicit provider configuration and opt-in terminal context |
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

The localhost dashboard is a functional console, not only a report viewer. It
lets you install modules, upload and statically inspect evidence, choose
uploaded artifacts for binary/memory/cloud/IOC analysis, correlate uploaded
logs, declare web scope, run passive web review, use optional local RE tools,
view reports, and download SARIF/STIX case exports.

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

### Authorized web and cloud review

```bash
cytool scope set --workspace research-lab \
  --engagement "Client review" --authorized-by client --domain example.com
cytool modules install web-scope-check --workspace research-lab
cytool web headers https://example.com --workspace research-lab --authorized
cytool web forms https://example.com/login --workspace research-lab --authorized

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

cytool-AI accepts OpenAI-compatible Chat Completions providers. It stores the
provider URL, model, and environment-variable name only—not the API key.

```bash
export OPENAI_API_KEY="..."
export CYTOOL_SERVER_KEY="local-server-secret"

cytool ai configure --base-url https://api.openai.com/v1 \
  --model gpt-5 --api-key-env OPENAI_API_KEY
cytool ai teach "Explain the latest binary report" --workspace research-lab
cytool ai fix "Prioritize these case findings" --workspace research-lab
```

Add `--terminal-context` only when you want to share a redacted snapshot of
`pwd`, `git status --short`, and `git diff --stat` from a chosen directory.

The local dashboard also serves `GET /v1/models` and authenticated
`POST /v1/chat/completions` for compatible local clients. It is localhost-only.

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
substitutions, downloads, network commands, and privilege escalation. Container
and remote runner profiles are descriptive in v0.1 and do not start anything.

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

Create a portable, complete ZIP backup of the workspace (including evidence,
reports, audit trail, and local indexes) before moving it to another approved
machine or retaining case records:

```bash
cytool backup --workspace research-lab --output ./research-lab-backup.zip
```

The project is MIT licensed, except for the explicitly attributed
Apache-2.0-derived approval utility documented in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

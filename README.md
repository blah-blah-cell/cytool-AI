# cytool-AI

`cytool-AI` is a local-first, modular cybersecurity automation platform for
authorized security research and defensive operations.

The first release is deliberately a small, inspectable foundation: a Linux CLI,
a signed-style module manifest format, selective module installation, project
workspaces, and an append-only audit log. It does not include active scanning or
exploit functionality.

## Principles

- **Authorization first.** Modules that can touch targets require an explicit
  authorization acknowledgement.
- **Local-first.** Findings and project data stay in the chosen workspace.
- **Modular by design.** Capabilities are opt-in; a registry controls what is
  available and installation records the exact module metadata used.
- **Auditable.** Every install and execution is recorded as JSON Lines.

## Capabilities in v0.1

- Offline artifact/binary fingerprinting: SHA-256/SHA-1, format hints, and
  printable strings from a supplied file—never execution.
- Memory capture, RE, cloud, log, and web workflows exposed as selective,
  auditable modules. Integrations are added only after review.
- Explicit per-workspace scope declarations; any supplied target is checked
  against approved domains before an execution request is recorded.
- Markdown evidence reports and provider-neutral AI bundles that stay local
  until the operator chooses a provider.
- A local-only JSON dashboard API (`/health`, `/api/modules`, `/api/audit`).

## AI assistant and terminal controls

cytool-AI works with any OpenAI-compatible Chat Completions provider. The
provider key is never saved to disk; only the name of its environment variable
is stored locally.

```bash
export OPENAI_API_KEY="..."
cytool ai configure --base-url https://api.openai.com/v1 --model gpt-5 --api-key-env OPENAI_API_KEY
cytool ai teach "Explain this ELF finding" --workspace research-lab --terminal-context
cytool ai fix "Review the latest audit events" --workspace research-lab
```

`--terminal-context` collects only `pwd`, `git status --short`, and `git diff
--stat` from an operator-selected directory; credentials are redacted before
being sent. `cytool terminal` uses three approval modes: `plan` (no execution),
`confirm` (preview only), and `approved` (executes only a small read-only
allowlist with no shell, redirects, pipes, downloads, privilege escalation, or
network commands).

For local client compatibility, run `cytool dashboard --workspace research-lab`
with `CYTOOL_SERVER_KEY` set. It provides a local authenticated
`POST /v1/chat/completions` proxy to your configured provider and must bind to
localhost.

## Quick start

Requires Python 3.11 or later.

```bash
python3 -m pip install -e .
cytool init research-lab
cytool modules list
cytool modules install artifact-inspector
cytool inspect ./suspicious-file --workspace research-lab --ai-bundle
cytool audit --workspace research-lab
```

The workspace is created beneath `~/.local/share/cytool-ai/workspaces` by
default. Override it with `CYTOOL_HOME`.

## Roadmap

1. Core workspace, module registry, audit trail, safe execution boundary.
2. Production-quality parsers and integrations for user-provided samples,
   memory captures, exported logs, and cloud evidence.
3. Sandboxed tool runners with reviewed, integrity-verified downloads.
4. Web-security and cloud-security automation constrained to declared,
   authorized targets.
5. Optional team dashboard, remote runners, and enterprise controls.

## Responsible use

Use cytool-AI only for systems, samples, and networks you own or have explicit
permission to assess. The project will keep modules scoped, observable, and
designed for legitimate research and defensive work.

## License

MIT. See [LICENSE](LICENSE).

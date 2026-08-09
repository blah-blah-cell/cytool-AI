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

## Quick start

Requires Python 3.11 or later.

```bash
python3 -m pip install -e .
cytool init research-lab
cytool modules list
cytool modules install artifact-inspector
cytool run artifact-inspector --workspace research-lab --authorized
cytool audit --workspace research-lab
```

The workspace is created beneath `~/.local/share/cytool-ai/workspaces` by
default. Override it with `CYTOOL_HOME`.

## Roadmap

1. Core workspace, module registry, audit trail, safe execution boundary.
2. Evidence ingestion and offline artifact triage.
3. Reverse-engineering and memory-forensics integrations for user-provided
   samples and captures.
4. Web-security and cloud-security workflows, constrained to declared,
   authorized targets.
5. Optional team dashboard, remote runners, and enterprise controls.

## Responsible use

Use cytool-AI only for systems, samples, and networks you own or have explicit
permission to assess. The project will keep modules scoped, observable, and
designed for legitimate research and defensive work.

## License

MIT. See [LICENSE](LICENSE).

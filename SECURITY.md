# Security policy

## Supported version

The current `main` branch and the latest stable release are supported.

## Reporting a vulnerability

Please do not open a public issue for a potential vulnerability. Use
**Security → Report a vulnerability** in this GitHub repository to submit a
private report with a concise reproduction, impact assessment, and relevant
sanitized logs. Do not include secrets, real client evidence, or live-target
details. You should receive an acknowledgement within seven days.

## Security boundaries

- The dashboard binds to localhost only and rejects untrusted Host/Origin
  headers; responses include restrictive browser security headers.
- Evidence is local unless an operator explicitly submits an AI request.
- Web workflows require a declared scope and explicit authorization.
- Samples are analyzed statically; cytool-AI does not execute uploaded files.
- Terminal context uses a no-shell allowlist and excludes commands that load or
  execute project code; Git helpers and optional locks are disabled.
- Downloaded tool packs use validated paths, bounded transfers, SHA-256
  verification, and atomic replacement; they are never auto-executed.

Use a dedicated analysis machine and appropriate isolation for untrusted or
potentially malicious samples.

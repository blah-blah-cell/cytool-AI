# Security policy

## Supported version

The current `main` branch and the latest tagged beta are supported.

## Reporting a vulnerability

Please do not open a public issue for a potential vulnerability. Email the
maintainer privately with a concise reproduction, impact assessment, and any
relevant logs. Do not include secrets, real client evidence, or live-target
details. You should receive an acknowledgement within seven days.

## Security boundaries

- The dashboard binds to localhost only.
- Evidence is local unless an operator explicitly submits an AI request.
- Web workflows require a declared scope and explicit authorization.
- Samples are analyzed statically; cytool-AI does not execute uploaded files.
- Downloaded tool packs are verified and stored; they are never auto-executed.

Use a dedicated analysis machine and appropriate isolation for untrusted or
potentially malicious samples.

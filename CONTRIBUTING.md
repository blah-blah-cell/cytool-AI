# Contributing to cytool-AI

Thanks for helping build an authorization-first security research tool.

## Local setup

```bash
python3 -m pip install -e . pytest
PYTHONPATH=src python3 -m pytest
bash scripts/smoke-test.sh
```

## Contribution rules

- Keep evidence workflows local and non-destructive by default.
- Every module must state its authorization requirement and have an executable,
  tested workflow before being listed in the registry.
- Do not add stealth, persistence, credential theft, payload injection, or
  unauthorized targeting features.
- Add tests for new behavior and run the full test suite before opening a PR.
- Preserve third-party licenses and attribution notices.

## Pull requests

Explain the user impact, the authorization/safety boundary, and how you tested
the change. Keep unrelated formatting changes out of the same pull request.

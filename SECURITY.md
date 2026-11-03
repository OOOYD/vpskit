# Security

See [docs/SECURITY.md](docs/SECURITY.md).

Quick rules:

- Do not commit `state/`, `build/`, `nodes.yaml`, `legacy/`.
- Do not push the old Git history: it contains live REALITY/SS secrets.
- Use `./vpskit plan` before `apply`; `apply`/`rollback`/`rotate` require explicit confirmation.
- Use `./scripts/check-secrets.sh` before publishing.

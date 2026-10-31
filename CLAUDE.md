# Working in this repository

Read `docs/architecture.md` and `docs/security.md` before changing anything structural.

## Non-negotiables
- **Adding a dependency**: never run `uv add` / `pip install` directly. Use `make add PKG=<name>`
  (runs `depguard` first). A PreToolUse hook in `.claude/settings.json` blocks unvetted installs.
- **Config**: new tunables go in `src/app/core/config.py` and `.env.example`, never as literals.
- **SQL**: SQLAlchemy expressions only. No f-string SQL, no `text()` with interpolated values.
- **Errors**: raise `AppError` subclasses from services; never return ad-hoc error dicts.
- **Secrets**: read via `SecretStr`; never log them. `redact_sensitive` covers common keys only.
- **Tests first**: every feature module ships with unit tests for its service and an integration
  test for its router. Coverage gate is 80% (`pytest` fails below it).

## Layout
`src/app/modules/<feature>/{models,schemas,repository,service,router}.py` — routers call services,
services call repositories, repositories own SQLAlchemy. Cross-cutting code lives in `core/`,
`middleware/`, `db/`, `infra/`. Third-party integrations are plugins (`docs/plugins.md`).

## Commands
`make install`, `make dev`, `make test`, `make lint`, `make audit`, `make outdated`, `make upgrade`.

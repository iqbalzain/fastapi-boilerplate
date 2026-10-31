# fastapi-boilerplate

A production-grade FastAPI service template. Secure by default, 12-factor compliant,
pluggable, and shipped with **dependency governance that enforces itself**: every package
added to this repo is vetted for authenticity, vulnerabilities, abandonment and licence
before it is installed, and the lockfile is re-audited on every commit, every PR and every week.

## Quick start

```bash
cp .env.example .env            # then set SECRET_KEY (python -c "import secrets; print(secrets.token_urlsafe(64))")
make install                    # uv sync + pre-commit hooks
make up                         # postgres + redis + migrations + API in Docker
# or locally:
docker compose up -d postgres redis && make migrate && make dev
open http://localhost:8000/docs
```

```bash
make test        # pytest, 80% coverage gate
make lint        # ruff, mypy --strict, bandit
make audit       # depguard policy audit + OSV + pip-audit
make outdated    # cooldown-aware upgrade report
make upgrade     # apply upgrades, re-vet, run tests
```

## What you get

| Concern | Implementation |
|---|---|
| Config | `pydantic-settings`, typed, validated at boot; production refuses weak/placeholder secrets, debug mode, insecure cookies, wildcard CORS/hosts |
| Logging | `structlog` JSON to stdout, request-scoped `request_id`, secret redaction |
| Errors | RFC 9457 `application/problem+json` everywhere; stack traces never leak |
| Auth | Argon2id passwords, short-lived JWT access tokens, rotating `HttpOnly` `__Host-` refresh cookies, revocation denylist, replay detection, timing-safe login |
| CSRF | Signed double-submit cookie middleware; bearer-token API clients exempt |
| Headers | CSP (deny-all for API, CDN-scoped for docs), HSTS, nosniff, frame-deny, COOP/CORP, Referrer- & Permissions-Policy |
| Abuse controls | Redis fixed-window rate limiting (global + per-route), body-size limit for declared *and* chunked bodies, trusted-host + strict CORS |
| Data | SQLAlchemy 2.0 async, repository pattern, Alembic async migrations, deterministic constraint names; raw SQL banned by lint |
| Extensibility | Plugin protocol + entry-point discovery; Prometheus and Sentry plugins included |
| Ops | Multi-stage distroless-ish image, non-root, read-only FS, health probes, graceful lifespan |
| Supply chain | `depguard` (stdlib-only) + Claude Code hook + pre-commit + CI + weekly workflow + Renovate config |

## Layout

```
src/app/
├── main.py            create_app() factory (uvicorn app.main:create_app --factory)
├── core/              config, logging, exceptions, security primitives, plugin registry, lifespan
├── middleware/        pure-ASGI: request context, security headers, body limit, rate limit, CSRF
├── db/                Base + mixins, engine/session factory, generic repository
├── infra/             redis client, rate limiter, token denylist
├── api/               dependencies (auth, db, rate limits) and the versioned router
├── modules/<feature>/ models · schemas · repository · service · router
└── plugins/           optional integrations (prometheus, sentry)
tools/depguard/        dependency governance CLI + Claude Code hook
tests/                 unit (pure) + integration (SQLite + fakeredis, full middleware stack)
docs/                  architecture, security, dependency governance, plugins, ADRs
```

## Adding a feature

1. `mkdir src/app/modules/widgets` with `models.py`, `schemas.py`, `repository.py`, `service.py`, `router.py`.
2. Services raise `AppError` subclasses; routers only translate HTTP ↔ schemas.
3. Register the router in `src/app/api/router.py`; import the model in `migrations/env.py`.
4. `make migration m="add widgets"` → review → `make migrate`.
5. Tests: unit-test the service, integration-test the router through `client` (see `tests/conftest.py`).

## Adding a dependency

```bash
make add PKG=httpx                 # vet → uv add (version pinned to the newest cooled-down release)
make add PKG=ruff ARGS="--group dev"
make vet PKG="some-package==1.2.3" # dry run
```

Direct `uv add`/`pip install` from Claude Code is intercepted by the hook in `.claude/settings.json`.
Policy lives in `depguard.toml`; see [docs/dependency-governance.md](docs/dependency-governance.md).

## 12-factor mapping

| Factor | Where |
|---|---|
| I Codebase · II Dependencies | one repo, `uv.lock` with hashes, `--frozen` installs |
| III Config | `core/config.py`, `.env.example`, no literals in code |
| IV Backing services | `DATABASE_URL`, `REDIS_URL`; swapped in tests for SQLite/fakeredis |
| V Build/release/run | Dockerfile stages, migrations as a separate one-shot service |
| VI Processes | stateless; sessions live in Redis/JWT |
| VII Port binding | uvicorn, `PORT` via CMD |
| VIII Concurrency | `--workers`, horizontal replicas, Redis-shared limits |
| IX Disposability | lifespan teardown, `/health/live` + `/health/ready` |
| X Dev/prod parity | same image + compose locally, same env surface |
| XI Logs | JSON event stream on stdout |
| XII Admin | Alembic via `make migrate` / the `migrate` service |

Further reading: [docs/architecture.md](docs/architecture.md) · [docs/security.md](docs/security.md) ·
[docs/dependency-governance.md](docs/dependency-governance.md) · [docs/plugins.md](docs/plugins.md) · [SECURITY.md](SECURITY.md)

# Architecture

## Layers and the dependency rule

```
router  ──►  service  ──►  repository  ──►  SQLAlchemy model
 (HTTP)      (domain)       (persistence)
```

* **Routers** parse/validate transport (Pydantic schemas with `extra="forbid"`), call one service
  method, and serialise the result. They never contain business rules or SQL.
* **Services** hold use-cases. They are plain Python: no FastAPI, no `Request`, no HTTP codes.
  Failures are `AppError` subclasses (`NotFoundError`, `ConflictError`, …) that the exception
  handlers turn into Problem Details responses.
* **Repositories** own queries. The generic `Repository[Model]` covers CRUD; feature repositories
  add typed queries. Only SQLAlchemy expressions are allowed (lint rule `S608` + review).
* **Models** are SQLAlchemy 2.0 declarative classes using `UUIDPrimaryKeyMixin` and `TimestampMixin`.

Imports flow left to right only. A service importing a router or FastAPI is a review blocker.

## Request lifecycle

```
RequestContext ─ SecurityHeaders ─ TrustedHost ─ CORS ─ BodyLimit ─ RateLimit ─ CSRF ─ ExceptionMiddleware ─ Router
```

Starlette treats the *last* `add_middleware` call as the outermost layer; `middleware/stack.py`
documents and owns the order. Every custom middleware is pure ASGI (no `BaseHTTPMiddleware`) so
streaming, `contextvars` and performance are preserved. Middleware that rejects a request writes
its own Problem Details response because `ExceptionMiddleware` sits *inside* the stack. The
body-limit middleware deliberately raises from within `receive()` so chunked overruns are rendered
by the normal handlers as 413.

## Dependency injection

`api/deps.py` is the only module that touches `request.app.state`. Resources created in the
lifespan (`db_sessionmaker`, `redis`, `rate_limiter`) are injected via `Annotated` aliases:
`DbSession`, `RedisDep`, `CurrentUser`, `SuperUser`, `SettingsDep`. Tests replace resources by
assigning fakes to `app.state` *before* the lifespan runs; the lifespan reuses what it finds.

## Configuration

`Settings` is frozen and validated once. Production mode adds invariants (secret strength, secure
cookies, JSON logs, no wildcards) so a misconfigured deploy fails at boot, not after an incident.
Add a setting → add it to `.env.example` in the same change.

## Plugins

Third-party integrations are isolated behind the `Plugin` protocol
(`core/plugins.py`) and loaded from `PLUGINS=` or entry points. They may add routes, middleware
and lifecycle hooks but cannot reach into feature modules. See `docs/plugins.md`.

## Persistence

Async SQLAlchemy with `asyncpg`; `pool_pre_ping` and recycling protect against stale connections.
One session per request with commit-on-success / rollback-on-error (`db/session.py`). Alembic runs
asynchronously and reads `DATABASE_URL` from settings; constraint names are deterministic through
`NAMING_CONVENTION`, which keeps autogenerate diffs clean.

## Testing strategy

* Unit tests target pure code (security primitives, config invariants, depguard heuristics).
* Integration tests boot the full app with SQLite + fakeredis through `httpx.ASGITransport`,
  exercising the real middleware stack, auth flow and error handlers.
* Coverage gate: 80% (`pytest` fails below). Plugins that depend on optional extras are excluded.

## Decisions

See `docs/adr/` for the recorded trade-offs (uv, token strategy, CSRF model, stdlib-only depguard).

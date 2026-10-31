# Security model

## Threats and controls

| Threat | Control | Where |
|---|---|---|
| Injection (SQL) | ORM/Core expressions only; `text()` with interpolation banned; bandit + ruff `S` rules | `db/`, CI |
| Injection (header/log) | Request-ID whitelist regex; structlog key/value logging; secret redaction processor | `middleware/request_context.py`, `core/logging.py` |
| Broken auth | Argon2id; JWT with `iss`/`aud`/`typ`/`jti`/`nbf`; 15-min access TTL; refresh rotation with replay detection; revocation denylist (fail-closed) | `core/security.py`, `modules/auth/`, `infra/token_store.py` |
| Credential stuffing / enumeration | Per-IP login limit (5/min); identical error for unknown user vs wrong password; dummy-hash verification equalises timing | `modules/auth/router.py`, `modules/users/service.py` |
| CSRF | Signed double-submit cookie; `SameSite`; `__Secure-` prefixed refresh cookie scoped to `/auth`; bearer clients exempt | `middleware/csrf.py` |
| XSS / clickjacking / MIME sniffing | Deny-all CSP for API, CDN-scoped CSP for docs; `X-Frame-Options`, `nosniff`, COOP/CORP, no-store | `middleware/security_headers.py` |
| Host header attacks | `TrustedHostMiddleware`; wildcard forbidden in production | `middleware/stack.py`, `core/config.py` |
| Cross-origin abuse | Explicit CORS allow-list, credentials only for listed origins, wildcard forbidden in production | `middleware/stack.py` |
| DoS (volume) | Redis fixed-window limiter, global + per-route, `Retry-After`; `/health` exempt | `infra/rate_limiter.py` |
| DoS (payload) | Content-Length check + streamed byte metering → 413 | `middleware/body_limit.py` |
| Mass assignment | All input schemas `extra="forbid"`; output schemas whitelist fields | `modules/*/schemas.py` |
| Information disclosure | Opaque 500s; docs disabled in production by default; no server header; `SecretStr` for secrets | `core/exceptions.py`, `main.py`, Dockerfile |
| Secrets in repo | `.env` gitignored; gitleaks pre-commit + CI; placeholder detection at boot | `.pre-commit-config.yaml`, `core/config.py` |
| Supply chain | depguard (typosquat, age, cooldown, yank, wheel, licence, OSV, provenance), hash-locked installs, pinned image, Trivy, Renovate cooldown | `tools/depguard/`, CI |
| Container escape / privilege | Non-root UID, `read_only`, `cap_drop: ALL`, `no-new-privileges` | Dockerfile, compose |

## Token flow

1. `POST /auth/login` → access token (JSON) + refresh token (`HttpOnly` cookie, path `/api/v1/auth`).
2. Client sends `Authorization: Bearer <access>` on API calls. CSRF middleware exempts these.
3. `POST /auth/refresh` (cookie only) → old refresh `jti` denylisted, new pair issued.
   Reusing a burned refresh token returns 401 "revoked" — a replay signal worth alerting on.
4. `POST /auth/logout` → both `jti`s denylisted until natural expiry; cookie cleared.

Browser clients that cannot use bearer tokens: call `GET /auth/csrf`, then echo the
`csrf_token` cookie in `X-CSRF-Token` on every unsafe request.

## Production checklist

- [ ] `ENVIRONMENT=production`, `LOG_FORMAT=json`, `COOKIE_SECURE=true` (enforced at boot)
- [ ] `SECRET_KEY` ≥ 32 random bytes from a secret manager; rotate → all tokens invalidate
- [ ] `TRUSTED_HOSTS` and `CORS_ALLOWED_ORIGINS` set to exact hosts
- [ ] Reverse proxy terminates TLS and sets `X-Forwarded-*`; uvicorn `--forwarded-allow-ips` lists only that proxy
- [ ] `DOCS_ENABLED` left unset (off) or docs behind the proxy's auth
- [ ] Redis reachable and persistent enough for the denylist TTL; `RATE_LIMIT_FAIL_OPEN` decided consciously
- [ ] `make audit` clean; CI `dependencies` job green; weekly `Dependency health` run reviewed

## Reporting

See [SECURITY.md](../SECURITY.md).

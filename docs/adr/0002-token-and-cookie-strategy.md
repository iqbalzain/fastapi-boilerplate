# ADR 0002 — Bearer access tokens + HttpOnly rotating refresh cookies

**Status**: accepted · 2026-10-31

## Context
Pure cookie sessions are CSRF-prone and need server-side session storage; pure bearer tokens in
`localStorage` are XSS-exfiltrable and cannot be revoked without state.

## Decision
* Access token: 15-minute JWT returned in the body, held in memory by clients, sent as `Bearer`.
* Refresh token: 7-day JWT in an `HttpOnly`, `Secure`, `SameSite` cookie with the `__Secure-` prefix,
  path-scoped to `/api/v1/auth` (`__Host-` would forbid the path) so it never rides along on ordinary API calls.
* Both carry `jti`; a Redis denylist (TTL = remaining life) supports logout, rotation and replay detection.
* Denylist lookups fail closed.

## Consequences
* XSS can use the access token for ≤15 min but cannot steal the refresh token.
* CSRF is limited to the `/auth` surface, which the CSRF middleware covers.
* Requires Redis; horizontal scaling works because state is shared.

# ADR 0003 — Signed double-submit CSRF tokens, bearer requests exempt

**Status**: accepted · 2026-10-31

## Context
Synchroniser tokens need server-side session state (we have none). Plain double-submit cookies are
defeated by an attacker who can set cookies on a sibling subdomain.

## Decision
Tokens are `nonce.hmac(secret, nonce)`; the middleware requires cookie == header *and* a valid
signature on every unsafe method, unless the request carries `Authorization: Bearer`, which
browsers cannot attach cross-site without a CORS preflight we control. Exempt paths are configurable
and empty by default.

## Consequences
* Stateless, horizontally scalable, immune to cookie-tossing.
* Browser clients must call `GET /auth/csrf` first; SPAs using bearer tokens need nothing.
* Rotating `SECRET_KEY` invalidates outstanding CSRF tokens (clients just refetch).

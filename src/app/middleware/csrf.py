"""CSRF protection using the signed double-submit cookie pattern.

Threat: a browser automatically attaches cookies (our refresh-token cookie) to
cross-site requests. Defence: every state-changing request that relies on
cookies must also carry a header whose value matches a cookie the attacker
cannot read. The token is HMAC-signed so a sibling-subdomain cannot plant one.

Requests authenticated with an ``Authorization: Bearer`` header are exempt —
custom headers cannot be set cross-origin without a CORS preflight, so they are
not forgeable by ambient authority.
"""

from __future__ import annotations

import hmac
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING

from app.core.security import verify_signed_value
from app.middleware._asgi import header, path_is_exempt, send_problem

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from app.core.config import Settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def cookie_value(scope: Scope, name: str) -> str | None:
    raw = header(scope, "cookie")
    if not raw:
        return None
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        return None
    morsel = jar.get(name)
    return morsel.value if morsel else None


def csrf_check_passes(settings: Settings, scope: Scope) -> bool:
    cookie = cookie_value(scope, settings.csrf_cookie_name)
    submitted = header(scope, settings.csrf_header_name)
    if not cookie or not submitted:
        return False
    if not hmac.compare_digest(cookie, submitted):
        return False
    return verify_signed_value(settings, cookie)


class CSRFMiddleware:
    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self.exempt = tuple(settings.csrf_exempt_paths)

    def _requires_check(self, scope: Scope) -> bool:
        if scope["method"] in SAFE_METHODS or path_is_exempt(scope["path"], self.exempt):
            return False
        auth = header(scope, "authorization")
        return not (auth and auth.lower().startswith("bearer "))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._requires_check(scope):
            await self.app(scope, receive, send)
            return
        if csrf_check_passes(self.settings, scope):
            await self.app(scope, receive, send)
            return
        await send_problem(
            scope,
            receive,
            send,
            status_code=403,
            title="Forbidden",
            detail="CSRF token missing or invalid.",
        )

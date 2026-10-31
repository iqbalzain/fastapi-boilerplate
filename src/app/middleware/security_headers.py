"""Defensive HTTP response headers.

API responses get a deny-all CSP. The interactive docs pages need to load
Swagger/ReDoc assets from jsdelivr, so they receive a relaxed policy scoped to
that CDN only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)
HSTS_VALUE = "max-age=63072000; includeSubDomains; preload"


@dataclass(frozen=True, slots=True)
class SecurityHeadersConfig:
    enable_hsts: bool
    docs_paths: tuple[str, ...] = ("/docs", "/redoc", "/openapi.json")

    def headers_for(self, path: str) -> list[tuple[bytes, bytes]]:
        is_docs = any(path.startswith(p) for p in self.docs_paths)
        pairs = {
            "content-security-policy": DOCS_CSP if is_docs else API_CSP,
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
            "cache-control": "no-store",
        }
        if self.enable_hsts:
            pairs["strict-transport-security"] = HSTS_VALUE
        return [(k.encode(), v.encode()) for k, v in pairs.items()]


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, config: SecurityHeadersConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        extra = self.config.headers_for(scope["path"])

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message.setdefault("headers", []).extend(
                    (k, v) for k, v in extra if k not in existing
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)

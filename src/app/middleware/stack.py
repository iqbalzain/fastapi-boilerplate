"""Assemble the middleware stack in one place so ordering is explicit.

Starlette treats the *last* ``add_middleware`` call as the outermost layer, so
the list below is written inner → outer and applied in that order:

    RequestContext → SecurityHeaders → TrustedHost → CORS → BodyLimit → RateLimit → CSRF → app
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.middleware.body_limit import BodySizeLimitMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_context import RequestContextMiddleware
from app.middleware.security_headers import SecurityHeadersConfig, SecurityHeadersMiddleware

if TYPE_CHECKING:
    from fastapi import FastAPI

    from app.core.config import Settings


def install_middleware(app: FastAPI, settings: Settings) -> None:
    if settings.csrf_enabled:
        app.add_middleware(CSRFMiddleware, settings=settings)
    if settings.rate_limit_enabled:
        app.add_middleware(
            RateLimitMiddleware,
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
            exempt_paths=tuple(
                f"{settings.api_prefix}{p}" for p in settings.rate_limit_exempt_paths
            ),
        )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", settings.csrf_header_name],
            expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
            max_age=600,
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    app.add_middleware(
        SecurityHeadersMiddleware,
        config=SecurityHeadersConfig(enable_hsts=settings.cookie_secure),
    )
    app.add_middleware(RequestContextMiddleware)

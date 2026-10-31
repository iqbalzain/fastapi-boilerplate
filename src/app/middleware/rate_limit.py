"""Global per-client rate limiting. Per-route limits live in ``app.api.deps``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.middleware._asgi import header, path_is_exempt, send_problem

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from app.infra.rate_limiter import RateLimiter


def client_key(scope: Scope) -> str:
    """Identify the caller. Proxy headers are honoured only when uvicorn is run
    with ``--proxy-headers --forwarded-allow-ips`` (it rewrites ``scope['client']``)."""
    client = scope.get("client")
    host = client[0] if client else "unknown"
    auth = header(scope, "authorization")
    # Authenticated callers are tracked by token to avoid punishing shared NATs.
    if auth and auth.lower().startswith("bearer "):
        return f"tok:{hash(auth) & 0xFFFFFFFF:x}"
    return f"ip:{host}"


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        limit: int,
        window_seconds: int,
        exempt_paths: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.limit = limit
        self.window_seconds = window_seconds
        self.exempt_paths = exempt_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or path_is_exempt(scope["path"], self.exempt_paths):
            await self.app(scope, receive, send)
            return

        limiter: RateLimiter | None = getattr(scope["app"].state, "rate_limiter", None)
        if limiter is None:  # lifespan not started (e.g. bare TestClient)
            await self.app(scope, receive, send)
            return

        decision = await limiter.hit(
            client_key(scope), limit=self.limit, window_seconds=self.window_seconds
        )
        rl_headers = {
            "X-RateLimit-Limit": str(decision.limit),
            "X-RateLimit-Remaining": str(decision.remaining),
        }
        if not decision.allowed:
            await send_problem(
                scope,
                receive,
                send,
                status_code=429,
                title="Too Many Requests",
                detail="Rate limit exceeded.",
                headers={**rl_headers, "Retry-After": str(decision.retry_after)},
            )
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend(
                    (k.lower().encode(), v.encode()) for k, v in rl_headers.items()
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)

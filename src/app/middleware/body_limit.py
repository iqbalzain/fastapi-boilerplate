"""Reject oversized request bodies before they reach a handler.

Declared ``Content-Length`` is checked up front; chunked bodies are metered as
they stream and aborted with 413 the moment the limit is crossed. Because the
framework turns any error raised while it reads the body into a generic 400,
the middleware also intercepts the outgoing response and replaces it with 413
when the limit was the cause.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.exceptions import PayloadTooLargeError, problem_response
from app.middleware._asgi import header, send_problem

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = header(scope, "content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await send_problem(
                scope,
                receive,
                send,
                status_code=413,
                title="Payload Too Large",
                detail=f"Request body exceeds {self.max_bytes} bytes.",
            )
            return

        received = 0
        exceeded = False
        replaced = False
        detail = f"Request body exceeds {self.max_bytes} bytes."

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise PayloadTooLargeError(detail)
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal replaced
            if not exceeded:
                await send(message)
                return
            if not replaced:  # swallow the app's error response, emit ours once
                replaced = True
                response = problem_response(
                    status_code=413,
                    title="Payload Too Large",
                    detail=detail,
                    instance=scope["path"],
                )
                await response(scope, receive, send)

        await self.app(scope, limited_receive, send_wrapper)

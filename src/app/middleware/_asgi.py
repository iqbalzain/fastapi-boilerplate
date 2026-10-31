"""Shared helpers for pure-ASGI middleware.

Pure ASGI (as opposed to ``BaseHTTPMiddleware``) avoids an extra task per
request, preserves streaming, and does not swallow ``contextvars``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.exceptions import problem_response

if TYPE_CHECKING:
    from collections.abc import Mapping

    from starlette.types import Receive, Scope, Send

type Headers = Mapping[str, str]


def header(scope: Scope, name: str) -> str | None:
    target = name.lower().encode("latin-1")
    for key, value in scope.get("headers", []):
        if key == target:
            return str(value.decode("latin-1"))
    return None


def path_is_exempt(path: str, exempt_prefixes: tuple[str, ...]) -> bool:
    return any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in exempt_prefixes
    )


async def send_problem(
    scope: Scope,
    receive: Receive,
    send: Send,
    *,
    status_code: int,
    title: str,
    detail: str,
    headers: Headers | None = None,
) -> None:
    response = problem_response(
        status_code=status_code,
        title=title,
        detail=detail,
        instance=scope.get("path"),
        headers=headers,
    )
    await response(scope, receive, send)

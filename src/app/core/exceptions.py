"""Domain error hierarchy and RFC 9457 (Problem Details) response handlers.

Services raise :class:`AppError` subclasses; nothing in the service layer
imports FastAPI. The handlers registered here translate them into a stable
``application/problem+json`` body. Unexpected exceptions are logged with full
context and returned as an opaque 500 so internals never leak to clients.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Mapping

log = get_logger(__name__)

PROBLEM_MEDIA_TYPE = "application/problem+json"


class AppError(Exception):
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    title: str = "Internal Server Error"
    type_uri: str = "about:blank"

    def __init__(
        self,
        detail: str | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        extras: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(detail or self.title)
        self.detail = detail
        self.headers = dict(headers or {})
        self.extras = dict(extras or {})


class BadRequestError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    title = "Bad Request"


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    title = "Unauthorized"

    def __init__(self, detail: str | None = None, **kwargs: Any) -> None:
        headers = {"WWW-Authenticate": "Bearer", **kwargs.pop("headers", {})}
        super().__init__(detail, headers=headers, **kwargs)


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    title = "Forbidden"


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    title = "Not Found"


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    title = "Conflict"


class PayloadTooLargeError(AppError):
    status_code = status.HTTP_413_CONTENT_TOO_LARGE
    title = "Payload Too Large"


class RateLimitedError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    title = "Too Many Requests"

    def __init__(self, retry_after: int, detail: str | None = None) -> None:
        super().__init__(detail, headers={"Retry-After": str(retry_after)})


class ServiceUnavailableError(AppError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    title = "Service Unavailable"


def problem_response(
    *,
    status_code: int,
    title: str,
    detail: str | None = None,
    instance: str | None = None,
    type_uri: str = "about:blank",
    headers: Mapping[str, str] | None = None,
    extras: Mapping[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"type": type_uri, "title": title, "status": status_code}
    if detail:
        body["detail"] = detail
    if instance:
        body["instance"] = instance
    body.update(extras or {})
    return JSONResponse(
        body, status_code=status_code, headers=dict(headers or {}), media_type=PROBLEM_MEDIA_TYPE
    )


async def _handle_app_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):  # pragma: no cover - registered for AppError only
        return await _handle_unexpected(request, exc)
    return problem_response(
        status_code=exc.status_code,
        title=exc.title,
        detail=exc.detail,
        instance=request.url.path,
        type_uri=exc.type_uri,
        headers=exc.headers,
        extras=exc.extras,
    )


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, HTTPException):  # pragma: no cover
        return await _handle_unexpected(request, exc)
    detail = exc.detail if isinstance(exc.detail, str) else None
    return problem_response(
        status_code=exc.status_code,
        title=_STATUS_TITLES.get(exc.status_code, "Error"),
        detail=detail,
        instance=request.url.path,
        headers=exc.headers,
    )


async def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        return await _handle_unexpected(request, exc)
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg"), "type": err.get("type")}
        for err in exc.errors()
    ]
    return problem_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        title="Validation Error",
        detail="Request did not pass validation.",
        instance=request.url.path,
        extras={"errors": errors},
    )


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled_exception", path=request.url.path, exc_type=type(exc).__name__)
    return problem_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Internal Server Error",
        detail="An unexpected error occurred.",
        instance=request.url.path,
    )


_STATUS_TITLES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    422: "Validation Error",
    429: "Too Many Requests",
}


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(HTTPException, _handle_http_exception)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(Exception, _handle_unexpected)

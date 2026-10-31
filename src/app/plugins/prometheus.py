"""Prometheus metrics plugin. Requires ``uv sync --extra observability``.

Enable with ``PLUGINS=app.plugins.prometheus:PrometheusPlugin``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from app.core.plugins import PluginError

if TYPE_CHECKING:
    from fastapi import FastAPI
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from app.core.config import Settings


class PrometheusPlugin:
    name = "prometheus"

    def setup(self, app: FastAPI, settings: Settings) -> None:
        try:
            from prometheus_client import (
                CONTENT_TYPE_LATEST,
                Counter,
                Histogram,
                generate_latest,
            )
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise PluginError("Install the 'observability' extra to use PrometheusPlugin") from exc

        from fastapi import Response

        requests_total = Counter(
            "http_requests_total", "HTTP requests", ["method", "path", "status"]
        )
        latency = Histogram("http_request_duration_seconds", "Request latency", ["method", "path"])

        class MetricsMiddleware:
            def __init__(self, inner: ASGIApp) -> None:
                self.inner = inner

            async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
                if scope["type"] != "http":
                    await self.inner(scope, receive, send)
                    return
                started = time.perf_counter()
                status_holder: dict[str, Any] = {"status": "500"}

                async def send_wrapper(message: Message) -> None:
                    if message["type"] == "http.response.start":
                        status_holder["status"] = str(message["status"])
                    await send(message)

                try:
                    await self.inner(scope, receive, send_wrapper)
                finally:
                    route = scope.get("route")
                    path = getattr(route, "path", scope["path"]) if route else scope["path"]
                    requests_total.labels(scope["method"], path, status_holder["status"]).inc()
                    latency.labels(scope["method"], path).observe(time.perf_counter() - started)

        app.add_middleware(MetricsMiddleware)

        @app.get("/metrics", include_in_schema=False)
        async def metrics() -> Response:
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

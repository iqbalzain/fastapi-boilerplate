"""Sentry error reporting plugin. Requires ``uv sync --extra observability``.

Enable with ``PLUGINS=app.plugins.sentry:SentryPlugin`` and set ``SENTRY_DSN``.
PII is never sent: ``send_default_pii`` stays off and request bodies are dropped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.logging import get_logger
from app.core.plugins import PluginError

if TYPE_CHECKING:
    from fastapi import FastAPI

    from app.core.config import Settings

log = get_logger(__name__)


class SentryPlugin:
    name = "sentry"

    def setup(self, app: FastAPI, settings: Settings) -> None:
        if settings.sentry_dsn is None:
            log.warning("sentry_plugin_disabled", reason="SENTRY_DSN not set")
            return
        try:
            import sentry_sdk
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise PluginError("Install the 'observability' extra to use SentryPlugin") from exc

        sentry_sdk.init(
            dsn=settings.sentry_dsn.get_secret_value(),
            environment=settings.environment.value,
            release=settings.app_version,
            send_default_pii=False,
            max_request_body_size="never",
            traces_sample_rate=0.0,
        )

"""Structured logging (12-factor XI: logs are event streams written to stdout).

Uses structlog with request-scoped context variables so every log line emitted
during a request carries ``request_id``, ``method`` and ``path`` automatically.
Standard-library loggers (uvicorn, sqlalchemy) are routed through the same
pipeline so output is uniform.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from app.core.config import Settings

_SENSITIVE_KEYS = frozenset(
    {"password", "passwd", "secret", "token", "authorization", "cookie", "set-cookie", "api_key"}
)
_REDACTED = "[REDACTED]"


def redact_sensitive(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Processor that scrubs well-known secret-bearing keys from log events."""
    return {
        key: (_REDACTED if key.lower() in _SENSITIVE_KEYS else value)
        for key, value in event_dict.items()
    }


def configure_logging(settings: Settings) -> None:
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        redact_sensitive,
    ]
    renderer: Any
    if settings.log_format == "json":
        shared_processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    # uvicorn's own access log duplicates our request log; keep its error log.
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]

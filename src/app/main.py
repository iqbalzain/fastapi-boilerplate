"""Application factory.

Run with ``uvicorn app.main:create_app --factory`` so nothing is constructed at
import time and tests can build isolated instances with their own settings.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.lifespan import lifespan
from app.core.logging import configure_logging
from app.core.plugins import PluginRegistry
from app.middleware.stack import install_middleware


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    docs = settings.docs_are_enabled
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    register_exception_handlers(app)
    install_middleware(app, settings)
    app.include_router(api_router, prefix=settings.api_prefix)

    registry = PluginRegistry.load(settings)
    registry.setup(app, settings)
    app.state.plugins = registry
    return app

"""Plugin system: the extension seam for third-party integrations.

A plugin is any object satisfying :class:`Plugin`. Plugins are discovered from
two places, in order:

1. ``Settings.plugins``: explicit ``"package.module:ClassName"`` strings.
2. Python entry points in the ``fastapi_boilerplate.plugins`` group, so an
   installed distribution can register itself without touching this codebase.

``setup`` runs synchronously while the app is being built (add routes,
middleware, exception handlers). ``startup``/``shutdown`` run inside the
lifespan with live resources available on ``app.state``.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from app.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from fastapi import FastAPI

    from app.core.config import Settings

ENTRY_POINT_GROUP = "fastapi_boilerplate.plugins"
log = get_logger(__name__)


class PluginError(RuntimeError):
    """Raised when a plugin cannot be loaded or configured."""


@runtime_checkable
class Plugin(Protocol):
    name: str

    def setup(self, app: FastAPI, settings: Settings) -> None: ...


@runtime_checkable
class LifecyclePlugin(Plugin, Protocol):
    async def startup(self, app: FastAPI) -> None: ...

    async def shutdown(self, app: FastAPI) -> None: ...


def _import_plugin(spec: str) -> Plugin:
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise PluginError(f"Plugin spec {spec!r} must look like 'package.module:ClassName'")
    try:
        module = importlib.import_module(module_name)
        factory = getattr(module, attr)
    except (ImportError, AttributeError) as exc:
        raise PluginError(f"Cannot import plugin {spec!r}: {exc}") from exc
    return _instantiate(factory, spec)


def _instantiate(factory: object, spec: str) -> Plugin:
    if isinstance(factory, type):
        instance: object = factory()
    elif isinstance(factory, Plugin):
        instance = factory
    elif callable(factory):
        instance = factory()
    else:
        raise PluginError(f"{spec!r} is neither a Plugin class, instance nor factory")
    if not isinstance(instance, Plugin):
        raise PluginError(f"{spec!r} does not implement the Plugin protocol")
    return instance


def _entry_point_plugins() -> Iterable[Plugin]:
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            yield _instantiate(ep.load(), ep.name)
        except PluginError:
            log.warning("plugin_entry_point_ignored", entry_point=ep.name)


@dataclass(frozen=True, slots=True)
class PluginRegistry:
    plugins: Sequence[Plugin] = field(default_factory=tuple)

    @classmethod
    def load(cls, settings: Settings) -> PluginRegistry:
        explicit = [_import_plugin(spec) for spec in settings.plugins]
        discovered = list(_entry_point_plugins())
        seen: set[str] = set()
        ordered: list[Plugin] = []
        for plugin in [*explicit, *discovered]:
            if plugin.name in seen:
                continue
            seen.add(plugin.name)
            ordered.append(plugin)
        return cls(plugins=tuple(ordered))

    def setup(self, app: FastAPI, settings: Settings) -> None:
        for plugin in self.plugins:
            plugin.setup(app, settings)
            log.info("plugin_loaded", plugin=plugin.name)

    async def startup(self, app: FastAPI) -> None:
        for plugin in self.plugins:
            if isinstance(plugin, LifecyclePlugin):
                await plugin.startup(app)

    async def shutdown(self, app: FastAPI) -> None:
        for plugin in reversed(self.plugins):
            if isinstance(plugin, LifecyclePlugin):
                await plugin.shutdown(app)

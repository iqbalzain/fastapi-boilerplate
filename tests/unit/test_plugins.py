import pytest
from fastapi import FastAPI

from app.core.plugins import PluginError, PluginRegistry
from tests.conftest import make_settings


class RecordingPlugin:
    name = "recording"
    events: list[str] = []

    def setup(self, app, settings):
        self.events.append("setup")

    async def startup(self, app):
        self.events.append("startup")

    async def shutdown(self, app):
        self.events.append("shutdown")


def recording_factory():
    return RecordingPlugin()


async def test_registry_runs_lifecycle_in_order():
    RecordingPlugin.events.clear()
    settings = make_settings(
        plugins="tests.unit.test_plugins:RecordingPlugin,tests.unit.test_plugins:recording_factory"
    )
    registry = PluginRegistry.load(settings)
    assert [p.name for p in registry.plugins] == ["recording"]  # de-duplicated by name
    app = FastAPI()
    registry.setup(app, settings)
    await registry.startup(app)
    await registry.shutdown(app)
    assert RecordingPlugin.events == ["setup", "startup", "shutdown"]


def test_bad_specs_raise_clear_errors():
    with pytest.raises(PluginError, match=r"package\.module:ClassName"):
        PluginRegistry.load(make_settings(plugins="nocolon"))
    with pytest.raises(PluginError, match="Cannot import"):
        PluginRegistry.load(make_settings(plugins="tests.unit.test_plugins:Missing"))
    with pytest.raises(PluginError, match="neither a Plugin"):
        PluginRegistry.load(make_settings(plugins="tests.unit.test_plugins:pytest"))

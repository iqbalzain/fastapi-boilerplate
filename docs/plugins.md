# Writing a plugin

A plugin packages a third-party integration so the core never imports it directly.

```python
# my_company/metrics_plugin.py
from fastapi import FastAPI
from app.core.config import Settings


class DatadogPlugin:
    name = "datadog"

    def setup(self, app: FastAPI, settings: Settings) -> None:
        # add routes / middleware / exception handlers; read config from `settings`
        ...

    async def startup(self, app: FastAPI) -> None:  # optional (LifecyclePlugin)
        app.state.datadog = await connect(...)

    async def shutdown(self, app: FastAPI) -> None:  # optional
        await app.state.datadog.close()
```

Enable it either way:

```bash
PLUGINS=my_company.metrics_plugin:DatadogPlugin,app.plugins.prometheus:PrometheusPlugin
```

```toml
# in the plugin's own pyproject.toml — auto-discovered when installed
[project.entry-points."fastapi_boilerplate.plugins"]
datadog = "my_company.metrics_plugin:DatadogPlugin"
```

Rules:

* Import optional SDKs **inside** `setup` and raise `PluginError` with the extra to install.
* New settings belong in `Settings` (typed, documented in `.env.example`), not `os.environ`.
* Plugins may read `app.state` resources created by the lifespan but must not import feature modules.
* Plugins are de-duplicated by `name`; explicit `PLUGINS=` entries win over entry points.
* Add the SDK with `make add PKG=… ARGS="--optional observability"` so it stays an extra.

Included: `app.plugins.prometheus:PrometheusPlugin` (`/metrics`, request counter + latency histogram)
and `app.plugins.sentry:SentryPlugin` (PII off, bodies never sent). Both need `uv sync --extra observability`.

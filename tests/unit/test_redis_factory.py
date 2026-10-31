from pydantic import SecretStr

from app.infra.redis import create_redis
from tests.conftest import make_settings


async def test_memory_url_returns_working_in_process_client():
    client = create_redis(make_settings(redis_url=SecretStr("memory://")))
    assert await client.ping()
    await client.set("k", "v", ex=10)
    assert await client.get("k") == "v"
    await client.aclose()


def test_real_url_returns_lazy_network_client():
    client = create_redis(make_settings(redis_url=SecretStr("redis://localhost:6399/3")))
    assert client.connection_pool.connection_kwargs["port"] == 6399

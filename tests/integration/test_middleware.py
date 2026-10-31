import pytest

from tests.conftest import build_app, login, make_settings, register


async def test_security_and_request_id_headers(client, api):
    resp = await client.get(f"{api}/health/live", headers={"X-Request-ID": "trace-42"})
    assert resp.headers["x-request-id"] == "trace-42"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["content-security-policy"].startswith("default-src 'none'")
    assert "strict-transport-security" not in resp.headers  # cookie_secure=False in tests
    assert resp.headers["cache-control"] == "no-store"


async def test_untrusted_host_rejected(client, api):
    resp = await client.get(f"{api}/health/live", headers={"host": "evil.example"})
    assert resp.status_code == 400


async def test_cors_preflight_for_allowed_origin(client, api):
    resp = await client.options(
        f"{api}/auth/login",
        headers={"Origin": "http://frontend.test", "Access-Control-Request-Method": "POST"},
    )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://frontend.test"
    assert "x-csrf-token" in resp.headers["access-control-allow-headers"].lower()

    denied = await client.get(f"{api}/health/live", headers={"Origin": "http://evil.test"})
    assert "access-control-allow-origin" not in denied.headers


async def test_body_limit_declared_and_streamed(client, api):
    settings_small = make_settings(max_request_body_bytes=1024)
    app = await build_app(settings_small)
    from asgi_lifespan import LifespanManager
    from httpx import ASGITransport, AsyncClient

    async with (
        LifespanManager(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c,
    ):
        big = {"email": "a@b.co", "password": "x" * 2000}
        resp = await c.post(f"{api}/users", json=big, headers={"Authorization": "Bearer x"})
        assert resp.status_code == 413

        async def chunks():
            yield b'{"email": "a@b.co", "password": "'
            yield b"x" * 2000
            yield b'"}'

        resp = await c.post(
            f"{api}/users",
            content=chunks(),
            headers={
                "Authorization": "Bearer x",
                "Content-Type": "application/json",
                "Transfer-Encoding": "chunked",
            },
        )
        assert resp.status_code == 413


async def test_csrf_enforced_for_cookie_clients(client, api):
    # No bearer header + no CSRF token → blocked.
    resp = await client.post(f"{api}/auth/login", json={"email": "a@b.co", "password": "x"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "CSRF token missing or invalid."

    # Fetch a token, echo it in the header → passes CSRF (then fails auth, as expected).
    token = (await client.get(f"{api}/auth/csrf")).json()["csrf_token"]
    assert client.cookies.get("csrf_token") == token
    resp = await client.post(
        f"{api}/auth/login",
        json={"email": "a@b.co", "password": "x"},
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 401

    # Header/cookie mismatch or forged signature → blocked.
    resp = await client.post(f"{api}/auth/login", json={}, headers={"X-CSRF-Token": token + "x"})
    assert resp.status_code == 403
    client.cookies.set("csrf_token", "forged.0000")
    resp = await client.post(f"{api}/auth/login", json={}, headers={"X-CSRF-Token": "forged.0000"})
    assert resp.status_code == 403


async def test_global_rate_limit(api):
    app = await build_app(make_settings(rate_limit_requests=3, rate_limit_window_seconds=60))
    from asgi_lifespan import LifespanManager
    from httpx import ASGITransport, AsyncClient

    async with (
        LifespanManager(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c,
    ):
        for i in range(3):
            resp = await c.get("/openapi.json")
            assert resp.status_code == 200
            assert resp.headers["x-ratelimit-remaining"] == str(2 - i)
        resp = await c.get("/openapi.json")
        assert resp.status_code == 429
        assert "retry-after" in resp.headers
        # health is exempt
        assert (await c.get(f"{api}/health/live")).status_code == 200


async def test_route_rate_limit_on_login(client, api):
    await register(client, api)
    for _ in range(5):
        await client.post(
            f"{api}/auth/login",
            json={"email": "alice@example.com", "password": "bad"},
            headers={"Authorization": "Bearer x"},
        )
    resp = await client.post(
        f"{api}/auth/login",
        json={"email": "alice@example.com", "password": "bad"},
        headers={"Authorization": "Bearer x"},
    )
    assert resp.status_code == 429
    assert resp.json()["title"] == "Too Many Requests"


async def test_rate_limiter_fails_open_when_redis_errors(client, api, app):
    from redis.exceptions import RedisError

    async def broken(*_, **__):
        raise RedisError("down")

    app.state.redis.set = broken
    assert (await client.get("/openapi.json")).status_code == 200


@pytest.mark.parametrize("fail_open", [False])
async def test_rate_limiter_fail_closed_option(api, fail_open):
    from redis.exceptions import RedisError

    app = await build_app(make_settings(rate_limit_fail_open=fail_open))
    from asgi_lifespan import LifespanManager
    from httpx import ASGITransport, AsyncClient

    async with (
        LifespanManager(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c,
    ):

        async def broken(*_, **__):
            raise RedisError("down")

        app.state.redis.set = broken
        assert (await c.get("/openapi.json")).status_code == 429


async def test_login_helper_smoke(client, api):
    await register(client, api)
    assert await login(client, api)

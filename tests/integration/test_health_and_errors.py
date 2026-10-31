async def test_liveness(client, api):
    resp = await client.get(f"{api}/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "checks": {}}


async def test_readiness(client, api):
    resp = await client.get(f"{api}/health/ready")
    assert resp.status_code == 200
    assert resp.json()["checks"] == {"database": "ok", "redis": "ok"}


async def test_readiness_degrades_when_redis_down(client, api, app):
    async def failing_ping():
        raise ConnectionError("down")

    app.state.redis.ping = failing_ping
    resp = await client.get(f"{api}/health/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["redis"] == "fail"


async def test_not_found_is_problem_json(client):
    resp = await client.get("/nope")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    assert resp.json()["title"] == "Not Found"


async def test_validation_error_shape(client, api):
    resp = await client.post(
        f"{api}/users", json={"email": "not-an-email"}, headers={"Authorization": "Bearer x"}
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["title"] == "Validation Error"
    assert any("password" in err["loc"] for err in body["errors"])


async def test_unknown_fields_are_rejected(client, api):
    payload = {"email": "a@b.co", "password": "x" * 12, "is_superuser": True}
    resp = await client.post(f"{api}/users", json=payload, headers={"Authorization": "Bearer x"})
    assert resp.status_code == 422


async def test_unexpected_exception_is_opaque(app):
    from httpx import ASGITransport, AsyncClient

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internals")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/boom")
    assert resp.status_code == 500
    assert "secret internals" not in resp.text
    assert resp.json()["title"] == "Internal Server Error"


async def test_docs_available_in_test_env(client):
    assert (await client.get("/openapi.json")).status_code == 200

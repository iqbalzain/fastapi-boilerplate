import uuid

from tests.conftest import USER_EMAIL, USER_PASSWORD, login, register

BEARER_EXEMPT = {"Authorization": "Bearer x"}


async def test_register_login_me_flow(client, api):
    user = await register(client, api)
    assert user["email"] == USER_EMAIL
    assert "hashed_password" not in user and "password" not in user

    token = await login(client, api)
    me = await client.get(f"{api}/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["id"] == user["id"]

    # refresh cookie is HttpOnly and path-scoped
    jar = [c for c in client.cookies.jar if c.name == "__Host-refresh_token"]
    assert jar and jar[0].path == f"{api}/auth"
    assert jar[0].has_nonstandard_attr("HttpOnly")


async def test_duplicate_registration_conflicts(client, api):
    await register(client, api)
    resp = await client.post(
        f"{api}/users",
        json={"email": USER_EMAIL.upper(), "password": USER_PASSWORD},
        headers=BEARER_EXEMPT,
    )
    assert resp.status_code == 409


async def test_login_failures_are_indistinguishable(client, api):
    await register(client, api)
    wrong_pw = await client.post(
        f"{api}/auth/login",
        json={"email": USER_EMAIL, "password": "nope-nope-nope"},
        headers=BEARER_EXEMPT,
    )
    no_user = await client.post(
        f"{api}/auth/login",
        json={"email": "ghost@example.com", "password": "nope-nope-nope"},
        headers=BEARER_EXEMPT,
    )
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json()["detail"] == no_user.json()["detail"]


async def test_protected_routes_require_valid_token(client, api):
    assert (await client.get(f"{api}/users/me")).status_code == 401
    assert (
        await client.get(f"{api}/users/me", headers={"Authorization": "Bearer garbage"})
    ).status_code == 401
    assert (
        await client.get(f"{api}/users/me", headers={"Authorization": "Basic abc"})
    ).status_code == 401


async def test_refresh_rotation_and_replay_detection(client, api):
    await register(client, api)
    await login(client, api)
    old_cookie = client.cookies.get("__Host-refresh_token")

    first = await client.post(f"{api}/auth/refresh", headers=BEARER_EXEMPT)
    assert first.status_code == 200
    new_cookie = client.cookies.get("__Host-refresh_token")
    assert new_cookie != old_cookie

    # Replaying the burned token must fail.
    client.cookies.set("__Host-refresh_token", old_cookie, path=f"{api}/auth")
    replay = await client.post(f"{api}/auth/refresh", headers=BEARER_EXEMPT)
    assert replay.status_code == 401
    assert "revoked" in replay.json()["detail"]

    client.cookies.delete("__Host-refresh_token", path=f"{api}/auth")
    assert (await client.post(f"{api}/auth/refresh", headers=BEARER_EXEMPT)).status_code == 401


async def test_logout_revokes_access_and_refresh(client, api):
    await register(client, api)
    token = await login(client, api)
    auth = {"Authorization": f"Bearer {token}"}
    assert (await client.post(f"{api}/auth/logout", headers=auth)).status_code == 204
    assert (await client.get(f"{api}/users/me", headers=auth)).status_code == 401
    assert client.cookies.get("__Host-refresh_token") is None


async def test_update_profile_and_admin_routes(client, api, app):
    user = await register(client, api)
    token = await login(client, api)
    auth = {"Authorization": f"Bearer {token}"}

    patched = await client.patch(
        f"{api}/users/me", json={"full_name": "Alice Liddell"}, headers=auth
    )
    assert patched.status_code == 200 and patched.json()["full_name"] == "Alice Liddell"

    assert (await client.get(f"{api}/users", headers=auth)).status_code == 403
    assert (await client.get(f"{api}/users/{user['id']}", headers=auth)).status_code == 403

    # promote to superuser directly in the DB
    from sqlalchemy import update

    from app.modules.users.models import User

    async with app.state.db_sessionmaker() as session:
        await session.execute(
            update(User).where(User.id == uuid.UUID(user["id"])).values(is_superuser=True)
        )
        await session.commit()

    listing = await client.get(f"{api}/users?limit=10", headers=auth)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert (await client.get(f"{api}/users/{user['id']}", headers=auth)).status_code == 200
    assert (await client.get(f"{api}/users/{uuid.uuid4()}", headers=auth)).status_code == 404


async def test_inactive_user_cannot_authenticate(client, api, app):
    user = await register(client, api)
    token = await login(client, api)
    from sqlalchemy import update

    from app.modules.users.models import User

    async with app.state.db_sessionmaker() as session:
        await session.execute(
            update(User).where(User.id == uuid.UUID(user["id"])).values(is_active=False)
        )
        await session.commit()
    assert (
        await client.get(f"{api}/users/me", headers={"Authorization": f"Bearer {token}"})
    ).status_code == 401
    resp = await client.post(
        f"{api}/auth/login",
        json={"email": USER_EMAIL, "password": USER_PASSWORD},
        headers=BEARER_EXEMPT,
    )
    assert resp.status_code == 401

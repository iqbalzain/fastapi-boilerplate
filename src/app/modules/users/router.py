import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CurrentUser, DbSession, RateLimit, SettingsDep, SuperUser
from app.core.exceptions import BadRequestError
from app.modules.users.schemas import Page, UserCreate, UserRead, UserUpdate
from app.modules.users.service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRead,
    dependencies=[Depends(RateLimit(10, 3600, scope="register"))],
    summary="Register a new account",
)
async def register(data: UserCreate, session: DbSession, settings: SettingsDep) -> UserRead:
    if len(data.password) < settings.password_min_length:
        raise BadRequestError(
            f"Password must be at least {settings.password_min_length} characters."
        )
    user = await UserService(session).register(data)
    return UserRead.model_validate(user)


@router.get("/me", response_model=UserRead, summary="Current user profile")
async def read_me(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)


@router.patch("/me", response_model=UserRead, summary="Update own profile")
async def update_me(data: UserUpdate, user: CurrentUser, session: DbSession) -> UserRead:
    updated = await UserService(session).update(user, data)
    return UserRead.model_validate(updated)


@router.get("", response_model=Page[UserRead], summary="List users (admin)")
async def list_users(
    _: SuperUser,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[UserRead]:
    users, total = await UserService(session).list(limit=limit, offset=offset)
    return Page(
        items=[UserRead.model_validate(u) for u in users], total=total, limit=limit, offset=offset
    )


@router.get("/{user_id}", response_model=UserRead, summary="Get a user (admin)")
async def read_user(user_id: uuid.UUID, _: SuperUser, session: DbSession) -> UserRead:
    return UserRead.model_validate(await UserService(session).get(user_id))

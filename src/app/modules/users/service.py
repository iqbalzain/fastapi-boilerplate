"""User use-cases. Pure domain logic: no HTTP, no FastAPI imports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import hash_password, verify_password
from app.modules.users.models import User
from app.modules.users.repository import UserRepository

if TYPE_CHECKING:
    import uuid
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.modules.users.schemas import UserCreate, UserUpdate


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.repo = UserRepository(session)

    async def register(self, data: UserCreate) -> User:
        if await self.repo.get_by_email(data.email) is not None:
            raise ConflictError("An account with this email already exists.")
        user = User(
            email=data.email,
            hashed_password=hash_password(data.password),
            full_name=data.full_name,
        )
        return await self.repo.add(user)

    async def get(self, user_id: uuid.UUID) -> User:
        user = await self.repo.get(user_id)
        if user is None:
            raise NotFoundError("User not found.")
        return user

    async def list(self, *, limit: int, offset: int) -> tuple[Sequence[User], int]:
        return await self.repo.list(limit=limit, offset=offset), await self.repo.count()

    async def update(self, user: User, data: UserUpdate) -> User:
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(user, field, value)
        await self.repo.session.flush()
        return user

    async def authenticate(self, email: str, password: str) -> User | None:
        """Constant-time-ish credential check; returns ``None`` on any failure."""
        user = await self.repo.get_by_email(email)
        valid, new_hash = verify_password(password, user.hashed_password if user else None)
        if not valid or user is None or not user.is_active:
            return None
        if new_hash:
            user.hashed_password = new_hash
            await self.repo.session.flush()
        return user

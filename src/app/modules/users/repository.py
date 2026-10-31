from __future__ import annotations

import uuid

from sqlalchemy import select

from app.db.repository import Repository
from app.modules.users.models import User


class UserRepository(Repository[User]):
    model = User

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email.lower())
        return await self.session.scalar(stmt)

    async def get_by_id_str(self, raw_id: str) -> User | None:
        try:
            pk = uuid.UUID(raw_id)
        except ValueError:
            return None
        return await self.get(pk)

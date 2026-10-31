"""Generic async repository. Feature modules subclass it with typed queries.

All queries go through SQLAlchemy Core/ORM expressions, which are always
parameterised: string-built SQL is forbidden by convention and by the
``S608`` ruff rule.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from app.db.base import Base

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession


class Repository[ModelT: Base]:
    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, pk: Any) -> ModelT | None:
        return await self.session.get(self.model, pk)

    async def list(self, *, limit: int = 50, offset: int = 0) -> Sequence[ModelT]:
        stmt = select(self.model).limit(limit).offset(offset)
        result = await self.session.scalars(stmt)
        return result.all()

    async def count(self) -> int:
        stmt = select(func.count()).select_from(self.model)
        return int(await self.session.scalar(stmt) or 0)

    async def add(self, instance: ModelT) -> ModelT:
        self.session.add(instance)
        await self.session.flush()
        return instance

    async def delete(self, instance: ModelT) -> None:
        await self.session.delete(instance)
        await self.session.flush()

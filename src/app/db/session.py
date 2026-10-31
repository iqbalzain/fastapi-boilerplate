"""Async engine / session factory construction and the per-request unit of work."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from app.core.config import Settings

SessionFactory = async_sessionmaker[AsyncSession]


def create_engine(settings: Settings) -> AsyncEngine:
    url = settings.database_url.get_secret_value()
    if settings.is_sqlite:
        # SQLite is for tests/local only; a shared in-memory DB needs StaticPool.
        return create_async_engine(
            url,
            echo=settings.database_echo,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
    return create_async_engine(
        url,
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


def create_session_factory(engine: AsyncEngine) -> SessionFactory:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def session_scope(factory: SessionFactory) -> AsyncIterator[AsyncSession]:
    """Session that commits on success and rolls back on any error.

    Implemented as a context manager (not a bare generator) so that an exception
    thrown into a dependency at ``yield`` reaches ``__aexit__`` immediately. A
    bare ``async for`` over a generator would leave the session to the garbage
    collector, deferring the rollback/close to some later point in the loop.
    """
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise

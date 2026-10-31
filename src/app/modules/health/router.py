"""Liveness/readiness probes for orchestrators (12-factor IX: disposability)."""

from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from app.api.deps import DbSession, RedisDep
from app.core.logging import get_logger

router = APIRouter(prefix="/health", tags=["health"])
log = get_logger(__name__)


class HealthStatus(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, Literal["ok", "fail"]]


@router.get("/live", summary="Process is up", response_model=HealthStatus)
async def live() -> HealthStatus:
    return HealthStatus(status="ok", checks={})


@router.get("/ready", summary="Dependencies are reachable", response_model=HealthStatus)
async def ready(
    request: Request,
    response: Response,
    session: DbSession,
    redis: RedisDep,
) -> HealthStatus:
    checks: dict[str, Literal["ok", "fail"]] = {}
    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        log.warning("readiness_db_failed", error=str(exc))
        checks["database"] = "fail"
    try:
        await redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        log.warning("readiness_redis_failed", error=str(exc))
        checks["redis"] = "fail"

    healthy = all(value == "ok" for value in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthStatus(status="ok" if healthy else "degraded", checks=checks)

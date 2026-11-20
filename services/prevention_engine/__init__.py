"""Prevention Engine Service Package."""

from __future__ import annotations

from typing import Any

from core.db import get_db_session
from services.prevention_engine.engine import PreventionEngine


def run_prevention_engine(client: Any | None = None) -> int:
    """Process one prevention-stream batch; returns the number of successes."""

    if client is None:
        from redis import Redis

        from core.config import settings

        client = Redis.from_url(settings.get_redis_url())
    with get_db_session() as db_session:
        report = PreventionEngine(db_session).run_once(client)
    return report.processed


__all__ = ["PreventionEngine", "run_prevention_engine"]

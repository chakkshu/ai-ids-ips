"""Celery Asynchronous Worker Service Package."""

from celery import Celery
from core.config import settings

celery_app = Celery(
    "ai_ids_ips_worker",
    broker=settings.get_redis_url(),
    backend=settings.get_redis_url(),
)

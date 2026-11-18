"""Registry DB tests that run against PostgreSQL via docker compose.

Skipped unless ``AI_IDS_TEST_DATABASE_URL`` is set; ``tests/conftest.py`` then
points the SQLAlchemy engine at that PostgreSQL instance.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from core.config import settings
from core.models.audit import AuditLog
from core.models.user import UserRole
from ml.registry import service, store
from ml.schema import MODEL_FEATURES

pytestmark = pytest.mark.skipif(
    not os.environ.get("AI_IDS_TEST_DATABASE_URL"),
    reason="PostgreSQL integration requires AI_IDS_TEST_DATABASE_URL",
)


def test_registry_lifecycle_on_postgres(
    tmp_path: Path, db_session: Any, make_user: Any
) -> None:
    assert settings.get_database_url().startswith("postgresql")

    root = tmp_path / "registry"
    work = tmp_path / "work"
    work.mkdir()
    for name in store.REQUIRED_ARTIFACTS:
        (work / name).write_text(f"synthetic test artifact {name}", encoding="utf-8")
    admin_id = make_user(username="pg-admin", role=UserRole.ADMIN)
    sources = {name: work / name for name in store.REQUIRED_ARTIFACTS}
    service.register_staged_version(
        "pg-v1",
        sources,
        {
            "feature_names": list(MODEL_FEATURES),
            "metrics": {"accuracy": 1.0},
            "dataset_hash": "0" * 64,
            "training_config": {"seed": 1},
        },
        db_session,
        root=root,
        actor_user_id=None,
    )
    db_session.flush()
    promoted = service.promote_version("pg-v1", admin_id, db_session, root=root)
    db_session.commit()

    assert promoted.status == "active"
    assert store.active_version(root) == "pg-v1"
    logs = db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
    assert any(entry.action == "MODEL_PROMOTED" for entry in logs)
    assert AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, logs) == []

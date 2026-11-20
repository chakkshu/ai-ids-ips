"""Phase 6 prevention stream consumer and decision orchestration."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from core.config import settings
from core.events import PreventionCandidateEvent
from core.logging import get_logger
from core.models.detection import Detection
from core.models.prevention import DecisionAction
from core.streams import BatchItem, ProcessingReport, StreamConsumer, StreamLimits
from prevention.ip_blocker import (
    BlockManager,
    DryRunAdapter,
    FirewallAdapter,
    get_adapter,
)
from prevention.policy import (
    PolicySettings,
    build_context,
    count_recent_candidates,
    evaluate,
    get_or_create_policy,
    persist_candidate,
    record_decision,
)
from utils.alerts import create_alert_from_decision
from utils.threat_intel import update_profile

logger = get_logger(__name__)


class PreventionEngine:
    """Consume candidate events, evaluate policy, and record every decision."""

    def __init__(
        self,
        db_session: Session,
        *,
        adapter: FirewallAdapter | None = None,
        admin_ip: str | None = None,
        actor_user_id: int | None = None,
    ) -> None:
        self.db = db_session
        self.adapter = adapter or get_adapter()
        self.admin_ip = admin_ip
        self.actor_user_id = actor_user_id

    def _adapter_for(self, event: PreventionCandidateEvent) -> FirewallAdapter:
        """Force dry-run for replayed/simulated events even in active mode."""

        if event.simulation and not isinstance(self.adapter, DryRunAdapter):
            return DryRunAdapter(self.adapter)
        return self.adapter

    def process_candidate(self, payload: Mapping[str, Any]) -> Any:
        """Validate, persist, evaluate, and act on one candidate event."""

        event = PreventionCandidateEvent.model_validate(dict(payload))
        candidate_row = persist_candidate(
            self.db, event.model_dump(mode="json"), observed_at=event.timestamp
        )
        candidate_payload = event.model_dump(mode="json")

        config = get_or_create_policy(self.db, actor_user_id=self.actor_user_id)
        policy = PolicySettings.from_config(config.config_json)
        now = event.timestamp or datetime.now(UTC)
        context = build_context(self.db, admin_ip=self.admin_ip, now=now)
        prior_count = count_recent_candidates(
            self.db,
            src_ip=event.src_ip,
            predicted_label=event.predicted_label,
            window_seconds=policy.window_seconds,
            now=now,
            exclude_candidate_id=event.candidate_id,
        )
        decision = evaluate(
            candidate_payload,
            policy=policy,
            context=context,
            repeat_count=prior_count + 1,
        )

        decision_row = record_decision(
            self.db,
            decision,
            candidate=candidate_payload,
            actor_user_id=self.actor_user_id,
        )
        if decision.action in {
            DecisionAction.BLOCK,
            DecisionAction.PENDING_APPROVAL,
        }:
            manager = BlockManager(
                self.db,
                self._adapter_for(event),
                actor_user_id=self.actor_user_id,
            )
            block = manager.block_ip(
                event.src_ip,
                reason=f"{decision.reason} ({event.predicted_label})",
                duration_minutes=decision.block_duration_minutes,
                decision_id=int(decision_row.id),
                requires_approval=decision.action == DecisionAction.PENDING_APPROVAL,
            )
            decision_row.block_id = int(block.id)
            self.db.flush()

        detection = None
        if candidate_row.detection_id is not None:
            detection = self.db.get(Detection, int(candidate_row.detection_id))
        if decision.action != DecisionAction.NO_ACTION and detection is not None:
            create_alert_from_decision(
                self.db,
                decision_row,
                detection=detection,
                severity=decision.severity,
            )
        update_profile(
            self.db,
            event.src_ip,
            attack_type=event.predicted_label,
            severity=decision.severity,
            detection=detection,
            resolve_dns=False,
        )
        candidate_row.processed = True
        self.db.flush()
        return decision_row

    def process_batch(
        self, items: Sequence[BatchItem]
    ) -> dict[str, BaseException | None]:
        """Process one stream batch, isolating per-event failures."""

        outcomes: dict[str, BaseException | None] = {}
        for payload, message_id in items:
            try:
                self.process_candidate(payload)
            except Exception as exc:  # noqa: BLE001 - dead-letter boundary
                logger.warning(
                    "Prevention candidate failed validation/processing: %s",
                    type(exc).__name__,
                )
                outcomes[message_id] = exc
            else:
                outcomes[message_id] = None
        return outcomes

    def make_consumer(self, client: Any) -> StreamConsumer:
        """Build a prevention-specific consumer group with retry/DLQ support."""

        return StreamConsumer(
            client,
            settings.STREAM_PREVENTION,
            settings.STREAM_PREVENTION_CONSUMER_GROUP,
            settings.STREAM_PREVENTION_CONSUMER_NAME,
            dead_letter_stream=settings.STREAM_PREVENTION_DEAD_LETTER,
            limits=StreamLimits(
                maxlen=settings.STREAM_MAXLEN,
                max_pending=settings.STREAM_MAX_PENDING,
                retry_limit=settings.STREAM_MAX_ATTEMPTS,
                batch_size=settings.STREAM_BATCH_SIZE,
                block_ms=settings.STREAM_BLOCK_MS,
            ),
        )

    def run_once(self, client: Any, *, block_ms: int | None = None) -> ProcessingReport:
        """Process one batch from the prevention stream and commit once."""

        consumer = self.make_consumer(client)
        report = consumer.process_batch(self.process_batch, block_ms=block_ms)
        self.db.commit()
        return report

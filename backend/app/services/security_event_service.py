from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import (
    SecurityEventRepository,
)
from app.schemas.security_event import SecurityEventCreate
from app.services.alert.service import AlertService
from app.services.detection.detection_engine import DetectionEngine
from app.services.detection.rule_provider import DetectionRuleProvider
from app.services.detection_match.service import DetectionMatchService
from app.services.detection_rule_service import DetectionRuleService
from app.services.security_event_ingestion import (
    SecurityEventIngestionResult,
)


class SecurityEventService:
    """Business logic for security event ingestion and retrieval."""

    def __init__(
        self,
        db: Session,
        detection_engine: DetectionEngine | None = None,
    ):
        self.security_event_repository = SecurityEventRepository(db)
        self.detection_match_service = DetectionMatchService(db)
        self.alert_service = AlertService(db)

        if detection_engine is not None:
            self.detection_engine = detection_engine
        else:
            detection_rule_service = DetectionRuleService(db)

            rule_provider = DetectionRuleProvider(
                detection_rule_service,
            )

            self.detection_engine = DetectionEngine(
                rule_provider=rule_provider,
            )

    def create_event(
        self,
        *,
        event: SecurityEventCreate,
    ) -> SecurityEvent:
        """Create a security event from a validated API payload."""

        return self.security_event_repository.create(
            event_type=event.event_type,
            severity=event.severity.value,
            source=event.source,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=event.username,
            hostname=event.hostname,
            message=event.message,
            event_timestamp=event.event_timestamp,
            metadata=event.metadata,
        )

    def create_event_with_detection(
        self,
        *,
        event: SecurityEventCreate,
    ) -> SecurityEventIngestionResult:
        """
        Create a security event, evaluate it against enabled
        detection rules, and persist detection matches and alerts.

        The event repository flushes the newly created event so that
        the event receives its database ID before detection evaluation.

        Each matching rule produces one DetectionMatch and one Alert.
        Existing event/rule matches and detection-match/alert pairs are
        reused so duplicate records are not created.
        """

        created_event = self.create_event(
            event=event,
        )

        detection_result = self.detection_engine.evaluate_event(
            event=created_event,
        )

        for rule in detection_result.matched_rules:
            detection_match = self.detection_match_service.create_match(
                security_event_id=created_event.id,
                detection_rule_id=rule.id,
                severity=rule.severity,
                matched_at=created_event.event_timestamp,
                metadata={
                    "rule_type": rule.rule_type,
                    "rule_name": rule.name,
                },
            )

            self.alert_service.create_alert(
                detection_match_id=detection_match.id,
                security_event_id=created_event.id,
                detection_rule_id=rule.id,
                severity=rule.severity,
                title=f"Detection rule matched: {rule.name}",
                description=(
                    rule.description
                    or created_event.message
                ),
                opened_at=created_event.event_timestamp,
            )

        return SecurityEventIngestionResult(
            event=created_event,
            detection_result=detection_result,
        )

    def get_event(
        self,
        *,
        event_id: int,
    ) -> SecurityEvent | None:
        """Retrieve a security event by ID."""

        return self.security_event_repository.get_by_id(
            event_id,
        )

    def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve security events using repository filters."""

        return self.security_event_repository.list_events(
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            source=source,
            start_time=start_time,
            end_time=end_time,
        )

    def search_events(
        self,
        *,
        query: str,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> tuple[list[SecurityEvent], int]:
        """Search security events using free-text and structured filters."""

        return self.security_event_repository.search_events(
            query=query,
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            source=source,
            start_time=start_time,
            end_time=end_time,
        )
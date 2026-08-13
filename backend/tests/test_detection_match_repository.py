from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.detection_match import DetectionMatch
from app.repositories.detection_match_repository import (
    DetectionMatchRepository,
)


def test_create_detection_match(db_session, security_event, detection_rule):
    repository = DetectionMatchRepository(db_session)

    match = repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
        metadata={"matched": True},
    )

    assert match.id is not None
    assert match.security_event_id == security_event.id
    assert match.detection_rule_id == detection_rule.id
    assert match.severity == "HIGH"
    assert match.status == "NEW"
    assert match.match_metadata == {"matched": True}


def test_get_detection_match_by_id(
    db_session,
    security_event,
    detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    created = repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
    )

    result = repository.get_by_id(created.id)

    assert result is not None
    assert result.id == created.id


def test_get_unknown_detection_match_returns_none(db_session):
    repository = DetectionMatchRepository(db_session)

    result = repository.get_by_id(999999)

    assert result is None


def test_get_detection_match_by_event_and_rule(
    db_session,
    security_event,
    detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    created = repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="MEDIUM",
    )

    result = repository.get_by_event_and_rule(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
    )

    assert result is not None
    assert result.id == created.id


def test_duplicate_event_rule_match_is_rejected(
    db_session,
    security_event,
    detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
    )

    with pytest.raises(IntegrityError):
        repository.create(
            security_event_id=security_event.id,
            detection_rule_id=detection_rule.id,
            severity="HIGH",
        )


def test_list_matches_filters_by_severity(
    db_session,
    security_event,
    detection_rule,
    another_security_event,
    another_detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
    )

    repository.create(
        security_event_id=another_security_event.id,
        detection_rule_id=another_detection_rule.id,
        severity="LOW",
    )

    results = repository.list_matches(
        severity="HIGH",
    )

    assert len(results) == 1
    assert results[0].severity == "HIGH"


def test_list_matches_filters_by_status(
    db_session,
    security_event,
    detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
        status="NEW",
    )

    results = repository.list_matches(
        status="NEW",
    )

    assert len(results) == 1
    assert results[0].status == "NEW"


def test_list_matches_filters_by_time_range(
    db_session,
    security_event,
    detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    matched_at = datetime(
        2026,
        8,
        12,
        12,
        0,
        tzinfo=timezone.utc,
    )

    repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
        matched_at=matched_at,
    )

    results = repository.list_matches(
        start_time=datetime(
            2026,
            8,
            12,
            11,
            0,
            tzinfo=timezone.utc,
        ),
        end_time=datetime(
            2026,
            8,
            12,
            13,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert len(results) == 1
    assert results[0].id is not None


def test_update_detection_match_status(
    db_session,
    security_event,
    detection_rule,
):
    repository = DetectionMatchRepository(db_session)

    match = repository.create(
        security_event_id=security_event.id,
        detection_rule_id=detection_rule.id,
        severity="HIGH",
    )

    updated = repository.update_status(
        match,
        status="RESOLVED",
    )

    assert updated.status == "RESOLVED"

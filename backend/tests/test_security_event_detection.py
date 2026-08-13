from datetime import datetime, timezone

from sqlalchemy import select

from app.models.detection_match import DetectionMatch
from app.models.detection_rule import DetectionRule
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.detection_rule_repository import (
    DetectionRuleRepository,
)
from app.security.password import hash_password
from app.schemas.security_event import SecurityEventCreate
from app.services.security_event_service import SecurityEventService


def _create_test_user(db_session) -> User:
    """Create a user for detection integration tests."""

    user = User(
        username="detection-match-integration-user",
        email="detection-match-integration-user@example.com",
        password_hash=hash_password("StrongPassword123!"),
        is_active=True,
        is_superuser=False,
    )

    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)

    return user


def _create_detection_rule(
    db_session,
    *,
    user_id: int,
    name: str,
    rule_type: str,
    severity: str,
    conditions: dict,
    enabled: bool = True,
) -> DetectionRule:
    """Create a detection rule for integration testing."""

    repository = DetectionRuleRepository(db_session)

    return repository.create(
        name=name,
        description="Security event detection integration test rule",
        rule_type=rule_type,
        severity=severity,
        conditions=conditions,
        enabled=enabled,
        created_by_user_id=user_id,
    )


def test_matching_event_creates_detection_match(db_session):
    """A matching security event creates one persisted detection match."""

    user = _create_test_user(db_session)

    rule = _create_detection_rule(
        db_session,
        user_id=user.id,
        name="detection-match-integration-brute-force",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    service = SecurityEventService(db_session)

    event_payload = SecurityEventCreate(
        event_type="LOGIN_FAILED",
        severity="HIGH",
        source="detection-match-integration-primary",
        source_ip="192.168.10.10",
        username="admin",
        hostname="auth-server",
        message="Failed SSH login attempt.",
        event_timestamp=datetime(
            2026,
            8,
            13,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        metadata={
            "attempt_count": 5,
        },
    )

    result = service.create_event_with_detection(
        event=event_payload,
    )

    db_session.commit()

    assert result.event.id is not None
    assert result.detection_result.event_id == result.event.id
    assert result.detection_result.evaluated_rule_count == 1
    assert len(result.detection_result.matched_rules) == 1
    assert result.detection_result.matched_rules[0].id == rule.id

    matches = list(
        db_session.scalars(
            select(DetectionMatch).where(
                DetectionMatch.security_event_id == result.event.id,
            )
        ).all()
    )

    assert len(matches) == 1

    match = matches[0]

    assert match.security_event_id == result.event.id
    assert match.detection_rule_id == rule.id
    assert match.severity == "HIGH"
    assert match.status == "NEW"
    assert match.matched_at == result.event.event_timestamp
    assert match.match_metadata["rule_type"] == "BRUTE_FORCE"
    assert (
        match.match_metadata["rule_name"]
        == "detection-match-integration-brute-force"
    )


def test_non_matching_event_creates_no_detection_match(db_session):
    """A non-matching security event creates no detection match."""

    user = _create_test_user(db_session)

    _create_detection_rule(
        db_session,
        user_id=user.id,
        name="detection-match-integration-non-match",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    service = SecurityEventService(db_session)

    event_payload = SecurityEventCreate(
        event_type="NORMAL_LOGIN",
        severity="LOW",
        source="detection-match-integration-non-match",
        username="normal-user",
        hostname="auth-server",
        message="Normal login.",
        event_timestamp=datetime(
            2026,
            8,
            13,
            11,
            0,
            tzinfo=timezone.utc,
        ),
    )

    result = service.create_event_with_detection(
        event=event_payload,
    )

    db_session.commit()

    assert result.event.id is not None
    assert result.detection_result.evaluated_rule_count == 1
    assert result.detection_result.matched_rules == ()

    matches = list(
        db_session.scalars(
            select(DetectionMatch).where(
                DetectionMatch.security_event_id == result.event.id,
            )
        ).all()
    )

    assert matches == []


def test_multiple_matching_rules_create_multiple_detection_matches(
    db_session,
):
    """Multiple matching rules create one match per rule."""

    user = _create_test_user(db_session)

    first_rule = _create_detection_rule(
        db_session,
        user_id=user.id,
        name="detection-match-integration-rule-one",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    second_rule = _create_detection_rule(
        db_session,
        user_id=user.id,
        name="detection-match-integration-rule-two",
        rule_type="SUSPICIOUS_LOGIN",
        severity="CRITICAL",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    service = SecurityEventService(db_session)

    event_payload = SecurityEventCreate(
        event_type="LOGIN_FAILED",
        severity="HIGH",
        source="detection-match-integration-multiple",
        source_ip="10.20.30.40",
        username="admin",
        hostname="auth-server",
        message="Multiple failed authentication attempts.",
        event_timestamp=datetime(
            2026,
            8,
            13,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    result = service.create_event_with_detection(
        event=event_payload,
    )

    db_session.commit()

    assert result.detection_result.evaluated_rule_count == 2
    assert len(result.detection_result.matched_rules) == 2

    matched_rule_ids = {
        rule.id
        for rule in result.detection_result.matched_rules
    }

    assert matched_rule_ids == {
        first_rule.id,
        second_rule.id,
    }

    matches = list(
        db_session.scalars(
            select(DetectionMatch).where(
                DetectionMatch.security_event_id == result.event.id,
            )
        ).all()
    )

    assert len(matches) == 2

    matched_detection_rule_ids = {
        match.detection_rule_id
        for match in matches
    }

    assert matched_detection_rule_ids == {
        first_rule.id,
        second_rule.id,
    }


def test_disabled_rule_does_not_create_detection_match(db_session):
    """A disabled matching rule must not create a detection match."""

    user = _create_test_user(db_session)

    rule = _create_detection_rule(
        db_session,
        user_id=user.id,
        name="detection-match-integration-disabled",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
        enabled=False,
    )

    service = SecurityEventService(db_session)

    event_payload = SecurityEventCreate(
        event_type="LOGIN_FAILED",
        severity="HIGH",
        source="detection-match-integration-disabled",
        username="admin",
        hostname="auth-server",
        message="Failed login attempt.",
        event_timestamp=datetime(
            2026,
            8,
            13,
            13,
            0,
            tzinfo=timezone.utc,
        ),
    )

    result = service.create_event_with_detection(
        event=event_payload,
    )

    db_session.commit()

    assert result.detection_result.evaluated_rule_count == 0
    assert result.detection_result.matched_rules == ()

    matches = list(
        db_session.scalars(
            select(DetectionMatch).where(
                DetectionMatch.security_event_id == result.event.id,
                DetectionMatch.detection_rule_id == rule.id,
            )
        ).all()
    )

    assert matches == []
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.models.detection_match import DetectionMatch
from app.services.detection_match.service import DetectionMatchService


def test_create_match_creates_new_match():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    expected_match = DetectionMatch(
        id=1,
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
        status="NEW",
        match_metadata={"matched": True},
    )

    repository.get_by_event_and_rule.return_value = None
    repository.create.return_value = expected_match

    result = service.create_match(
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
        metadata={"matched": True},
    )

    repository.get_by_event_and_rule.assert_called_once_with(
        security_event_id=10,
        detection_rule_id=20,
    )

    repository.create.assert_called_once_with(
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
        status="NEW",
        matched_at=None,
        metadata={"matched": True},
    )

    assert result is expected_match


def test_create_match_returns_existing_match():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    existing_match = DetectionMatch(
        id=1,
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
        status="NEW",
    )

    repository.get_by_event_and_rule.return_value = existing_match

    result = service.create_match(
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
    )

    repository.get_by_event_and_rule.assert_called_once_with(
        security_event_id=10,
        detection_rule_id=20,
    )

    repository.create.assert_not_called()

    assert result is existing_match


def test_get_match_returns_match():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    expected_match = MagicMock(spec=DetectionMatch)

    repository.get_by_id.return_value = expected_match

    result = service.get_match(
        match_id=1,
    )

    repository.get_by_id.assert_called_once_with(1)

    assert result is expected_match


def test_get_match_returns_none_for_unknown_match():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    repository.get_by_id.return_value = None

    result = service.get_match(
        match_id=999,
    )

    repository.get_by_id.assert_called_once_with(999)

    assert result is None


def test_get_match_by_event_and_rule():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    expected_match = MagicMock(spec=DetectionMatch)

    repository.get_by_event_and_rule.return_value = expected_match

    result = service.get_match_by_event_and_rule(
        security_event_id=10,
        detection_rule_id=20,
    )

    repository.get_by_event_and_rule.assert_called_once_with(
        security_event_id=10,
        detection_rule_id=20,
    )

    assert result is expected_match


def test_list_matches_passes_filters_to_repository():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    expected_matches = [
        MagicMock(spec=DetectionMatch),
        MagicMock(spec=DetectionMatch),
    ]

    repository.list_matches.return_value = expected_matches

    start_time = datetime(
        2026,
        8,
        1,
        tzinfo=timezone.utc,
    )

    end_time = datetime(
        2026,
        8,
        12,
        tzinfo=timezone.utc,
    )

    result = service.list_matches(
        limit=50,
        offset=10,
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
        status="NEW",
        start_time=start_time,
        end_time=end_time,
    )

    repository.list_matches.assert_called_once_with(
        limit=50,
        offset=10,
        security_event_id=10,
        detection_rule_id=20,
        severity="HIGH",
        status="NEW",
        start_time=start_time,
        end_time=end_time,
    )

    assert result == expected_matches


def test_update_status_updates_existing_match():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    existing_match = MagicMock(spec=DetectionMatch)

    repository.get_by_id.return_value = existing_match
    repository.update_status.return_value = existing_match

    result = service.update_status(
        match_id=1,
        status="RESOLVED",
    )

    repository.get_by_id.assert_called_once_with(1)

    repository.update_status.assert_called_once_with(
        existing_match,
        status="RESOLVED",
    )

    assert result is existing_match


def test_update_status_returns_none_for_unknown_match():
    db = MagicMock()

    repository = MagicMock()

    service = DetectionMatchService(db)

    service.detection_match_repository = repository

    repository.get_by_id.return_value = None

    result = service.update_status(
        match_id=999,
        status="RESOLVED",
    )

    repository.get_by_id.assert_called_once_with(999)

    repository.update_status.assert_not_called()

    assert result is None
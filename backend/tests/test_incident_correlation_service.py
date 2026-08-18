from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.user import User
from app.repositories.alert.correlation_repository import CorrelationCandidate
from app.repositories.detection_rule_repository import DetectionRuleRepository
from app.schemas.security_event import SecurityEventCreate
from app.security.password import hash_password
from app.services.incident.correlation import IncidentCorrelationService
from app.services.security_event_service import SecurityEventService


def _event(**overrides):
    values = {"event_type": "LOGIN_FAILED", "source_ip": "203.0.113.10", "destination_ip": "10.0.0.10", "username": "admin", "hostname": "auth-01"}
    values.update(overrides)
    return SimpleNamespace(**values)


def test_candidate_selection_requires_same_event_type_and_entity():
    service = IncidentCorrelationService(SimpleNamespace())
    incident = SimpleNamespace(id=22)
    assert service._select_candidate(event=_event(), candidates=[CorrelationCandidate(incident, _event(source_ip="198.51.100.9"))]) is incident
    assert service._select_candidate(event=_event(), candidates=[CorrelationCandidate(incident, _event(event_type="MALWARE_DETECTED"))]) is None


def test_entity_matching_ignores_empty_values():
    assert not IncidentCorrelationService._shares_entity_identifier(
        _event(source_ip="", destination_ip=None, username=None, hostname=None),
        _event(source_ip="", destination_ip=None, username=None, hostname=None),
    )


@pytest.fixture
def correlation_user(db_session):
    user = User(username="detection-match-integration-correlation-user", email="detection-match-integration-correlation@example.com", password_hash=hash_password("StrongPassword123!"), is_active=True, is_superuser=False)
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def correlation_rule(db_session, correlation_user):
    return DetectionRuleRepository(db_session).create(
        name="detection-match-integration-correlation-rule",
        description="Correlation integration test rule",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={"event_type": "LOGIN_FAILED"},
        enabled=True,
        created_by_user_id=correlation_user.id,
    )


@pytest.fixture(autouse=True)
def remove_automated_test_incidents(db_session):
    yield
    incident_ids = list(db_session.scalars(select(Incident.id).where(Incident.title.like("Automated incident: Detection rule matched: detection-match-integration-correlation-rule%"))))
    if incident_ids:
        db_session.execute(delete(Alert).where(Alert.incident_id.in_(incident_ids)))
        db_session.execute(delete(Incident).where(Incident.id.in_(incident_ids)))
        db_session.commit()


def _ingest(service, *, timestamp, source_ip, username="admin", hostname="correlation-auth-01"):
    return service.create_event_with_detection(
        event=SecurityEventCreate(
            event_type="LOGIN_FAILED",
            severity="HIGH",
            source="detection-match-integration-correlation",
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            message="Correlation test login failure.",
            event_timestamp=timestamp,
        )
    )


def _alerts_for_events(db_session, event_ids):
    return list(db_session.scalars(select(Alert).where(Alert.security_event_id.in_(event_ids)).order_by(Alert.id)))


def test_ingestion_creates_and_reuses_automated_incident(db_session, correlation_rule):
    service = SecurityEventService(db_session)
    first = _ingest(service, timestamp=datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc), source_ip="203.0.113.50")
    second = _ingest(service, timestamp=datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc), source_ip="203.0.113.50")
    db_session.commit()
    alerts = _alerts_for_events(db_session, [first.event.id, second.event.id])
    assert len(alerts) == 2
    assert alerts[0].incident_id == alerts[1].incident_id
    incident = db_session.get(Incident, alerts[0].incident_id)
    system_user = db_session.scalar(select(User).where(User.username == "system"))
    assert incident is not None
    assert incident.created_by_user_id == system_user.id
    assert incident.status == "OPEN"


def test_ingestion_does_not_correlate_different_entities_or_old_alerts(db_session, correlation_rule):
    service = SecurityEventService(db_session)
    first = _ingest(service, timestamp=datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc), source_ip="203.0.113.60", username="first-user", hostname="first-host")
    different_entity = _ingest(service, timestamp=datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc), source_ip="203.0.113.61", username="second-user", hostname="second-host")
    old_window = _ingest(service, timestamp=datetime(2026, 8, 16, 10, 1, tzinfo=timezone.utc), source_ip="203.0.113.60", username="first-user", hostname="first-host")
    db_session.commit()
    alerts = _alerts_for_events(db_session, [first.event.id, different_entity.event.id, old_window.event.id])
    assert len({alert.incident_id for alert in alerts}) == 3


def test_correlating_an_attached_alert_is_idempotent(db_session, correlation_rule):
    result = _ingest(SecurityEventService(db_session), timestamp=datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc), source_ip="203.0.113.70")
    alert = _alerts_for_events(db_session, [result.event.id])[0]
    original_incident_id = alert.incident_id
    correlation = IncidentCorrelationService(db_session).correlate_alert(alert=alert)
    assert correlation.incident.id == original_incident_id
    assert not correlation.created
    assert alert.incident_id == original_incident_id

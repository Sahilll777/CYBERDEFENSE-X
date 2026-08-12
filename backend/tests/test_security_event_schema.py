import pytest
from pydantic import ValidationError

from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventSeverity,
)


def test_security_event_create_accepts_valid_payload():
    event = SecurityEventCreate(
        event_type="LOGIN_FAILED",
        severity="HIGH",
        source="linux-server",
        source_ip="192.168.1.10",
        username="admin",
        hostname="server-01",
        message="Failed login attempt detected.",
        event_timestamp="2026-08-12T10:30:00Z",
        metadata={
            "attempt_count": 5,
            "authentication_method": "ssh",
        },
    )

    assert event.event_type == "LOGIN_FAILED"
    assert event.severity == SecurityEventSeverity.HIGH
    assert event.source == "linux-server"
    assert event.source_ip == "192.168.1.10"
    assert event.metadata["attempt_count"] == 5


def test_security_event_create_defaults_metadata_to_empty_dictionary():
    event = SecurityEventCreate(
        event_type="SYSTEM_START",
        severity="LOW",
        source="linux-server",
        message="System started.",
        event_timestamp="2026-08-12T10:30:00Z",
    )

    assert event.metadata == {}


def test_security_event_create_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            event_type="LOGIN_FAILED",
            severity="INVALID",
            source="linux-server",
            message="Failed login attempt.",
            event_timestamp="2026-08-12T10:30:00Z",
        )


def test_security_event_create_rejects_empty_event_type():
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            event_type="",
            severity="HIGH",
            source="linux-server",
            message="Failed login attempt.",
            event_timestamp="2026-08-12T10:30:00Z",
        )


def test_security_event_create_rejects_empty_message():
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            event_type="LOGIN_FAILED",
            severity="HIGH",
            source="linux-server",
            message="",
            event_timestamp="2026-08-12T10:30:00Z",
        )
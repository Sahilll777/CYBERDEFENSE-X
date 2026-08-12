from datetime import datetime, timezone

import pytest

from app.models.detection_rule import DetectionRule
from app.models.security_event import SecurityEvent
from app.services.detection.rule_evaluator import (
    RuleEvaluationResult,
    RuleEvaluator,
)


def create_event(**overrides) -> SecurityEvent:
    """Create an in-memory security event for evaluator tests."""

    values = {
        "id": 1001,
        "event_type": "LOGIN_FAILED",
        "severity": "HIGH",
        "source": "linux",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "username": "root",
        "hostname": "server-01",
        "message": "Failed SSH login attempt",
        "event_timestamp": datetime.now(timezone.utc),
        "event_metadata": {},
    }

    values.update(overrides)

    return SecurityEvent(**values)


def create_rule(**overrides) -> DetectionRule:
    """Create an in-memory detection rule for evaluator tests."""

    values = {
        "id": 2001,
        "name": "SSH Brute Force",
        "description": "Detect failed SSH logins",
        "rule_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "conditions": {
            "event_type": "LOGIN_FAILED",
        },
        "enabled": True,
        "created_by_user_id": 1,
    }

    values.update(overrides)

    return DetectionRule(**values)


def test_matching_rule_returns_match():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        conditions={
            "event_type": "LOGIN_FAILED",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert isinstance(result, RuleEvaluationResult)
    assert result.matched is True
    assert result.rule_id == 2001
    assert result.event_id == 1001


def test_non_matching_rule_returns_no_match():
    evaluator = RuleEvaluator()

    event = create_event(
        event_type="LOGIN_SUCCESS",
    )

    rule = create_rule(
        conditions={
            "event_type": "LOGIN_FAILED",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is False
    assert result.rule_id == 2001
    assert result.event_id == 1001


def test_multiple_conditions_use_and_semantics():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        conditions={
            "event_type": "LOGIN_FAILED",
            "severity": "HIGH",
            "source": "linux",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is True


def test_multiple_conditions_fail_when_one_condition_does_not_match():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        conditions={
            "event_type": "LOGIN_FAILED",
            "severity": "CRITICAL",
            "source": "linux",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is False


def test_disabled_rule_does_not_match():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        enabled=False,
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is False


def test_event_type_comparison_is_case_insensitive():
    evaluator = RuleEvaluator()

    event = create_event(
        event_type="LOGIN_FAILED",
    )

    rule = create_rule(
        conditions={
            "event_type": "login_failed",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is True


def test_string_comparison_trims_whitespace():
    evaluator = RuleEvaluator()

    event = create_event(
        source="linux",
    )

    rule = create_rule(
        conditions={
            "source": "  LINUX  ",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is True


@pytest.mark.parametrize(
    "field_name",
    [
        "severity",
        "source",
        "source_ip",
        "destination_ip",
        "username",
        "hostname",
        "message",
    ],
)
def test_supported_event_fields_can_be_evaluated(field_name):
    evaluator = RuleEvaluator()

    event = create_event()

    expected_value = getattr(event, field_name)

    rule = create_rule(
        conditions={
            field_name: expected_value,
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is True


def test_non_matching_message_returns_no_match():
    evaluator = RuleEvaluator()

    event = create_event(
        message="Successful SSH login",
    )

    rule = create_rule(
        conditions={
            "message": "Failed SSH login attempt",
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is False


def test_none_condition_matches_none_event_value():
    evaluator = RuleEvaluator()

    event = create_event(
        source_ip=None,
    )

    rule = create_rule(
        conditions={
            "source_ip": None,
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is True


def test_none_condition_does_not_match_non_none_event_value():
    evaluator = RuleEvaluator()

    event = create_event(
        source_ip="192.168.1.50",
    )

    rule = create_rule(
        conditions={
            "source_ip": None,
        }
    )

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    assert result.matched is False


def test_unsupported_condition_field_is_rejected():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        conditions={
            "process_name": "sshd",
        }
    )

    with pytest.raises(
        ValueError,
        match="Unsupported detection rule condition field",
    ):
        evaluator.evaluate(
            event=event,
            rule=rule,
        )


def test_empty_conditions_are_rejected():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        conditions={},
    )

    with pytest.raises(
        ValueError,
        match="at least one condition",
    ):
        evaluator.evaluate(
            event=event,
            rule=rule,
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        {},
        [],
        ["LOGIN_FAILED"],
        {"value": "LOGIN_FAILED"},
    ],
)
def test_complex_condition_values_are_rejected(invalid_value):
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule(
        conditions={
            "event_type": invalid_value,
        }
    )

    with pytest.raises(
        ValueError,
        match="must be a scalar",
    ):
        evaluator.evaluate(
            event=event,
            rule=rule,
        )


def test_evaluation_result_is_immutable():
    evaluator = RuleEvaluator()

    event = create_event()

    rule = create_rule()

    result = evaluator.evaluate(
        event=event,
        rule=rule,
    )

    with pytest.raises(AttributeError):
        result.matched = False
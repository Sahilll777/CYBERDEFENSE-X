from datetime import datetime, timezone

import pytest

from app.models.detection_rule import DetectionRule
from app.models.security_event import SecurityEvent
from app.services.detection.detection_engine import (
    DetectionEngine,
)
from app.services.detection.rule_evaluator import RuleEvaluator


class FakeRuleProvider:
    """In-memory rule provider for detection engine tests."""

    def __init__(self, rules):
        self.rules = list(rules)
        self.call_count = 0

    def list_enabled_rules(self):
        self.call_count += 1
        return list(self.rules)


def create_event(**overrides) -> SecurityEvent:
    values = {
        "id": 5001,
        "event_type": "LOGIN_FAILED",
        "severity": "HIGH",
        "source": "linux",
        "source_ip": "10.0.0.15",
        "destination_ip": "10.0.0.10",
        "username": "root",
        "hostname": "server-01",
        "message": "Failed SSH login attempt",
        "event_timestamp": datetime.now(timezone.utc),
        "event_metadata": {},
    }

    values.update(overrides)

    return SecurityEvent(**values)


def create_rule(
    *,
    rule_id: int,
    name: str,
    conditions: dict,
    enabled: bool = True,
    rule_type: str = "TEST",
    severity: str = "HIGH",
) -> DetectionRule:
    return DetectionRule(
        id=rule_id,
        name=name,
        description=None,
        rule_type=rule_type,
        severity=severity,
        conditions=conditions,
        enabled=enabled,
        created_by_user_id=1,
    )


def test_engine_returns_matching_rules():
    event = create_event()

    matching_rule = create_rule(
        rule_id=1,
        name="Failed Login Detection",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    non_matching_rule = create_rule(
        rule_id=2,
        name="Malware Detection",
        conditions={
            "event_type": "MALWARE_DETECTED",
        },
    )

    provider = FakeRuleProvider(
        [
            matching_rule,
            non_matching_rule,
        ]
    )

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert result.event_id == event.id
    assert result.evaluated_rule_count == 2
    assert result.matched_rules == (matching_rule,)


def test_engine_returns_all_matching_rules():
    event = create_event()

    rule_one = create_rule(
        rule_id=1,
        name="Login Failure",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    rule_two = create_rule(
        rule_id=2,
        name="High Severity",
        conditions={
            "severity": "HIGH",
        },
    )

    rule_three = create_rule(
        rule_id=3,
        name="Malware",
        conditions={
            "event_type": "MALWARE_DETECTED",
        },
    )

    provider = FakeRuleProvider(
        [
            rule_one,
            rule_two,
            rule_three,
        ]
    )

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert result.matched_rules == (
        rule_one,
        rule_two,
    )


def test_engine_only_evaluates_enabled_rules():
    event = create_event()

    enabled_rule = create_rule(
        rule_id=1,
        name="Enabled Rule",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
        enabled=True,
    )

    disabled_rule = create_rule(
        rule_id=2,
        name="Disabled Rule",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
        enabled=False,
    )

    provider = FakeRuleProvider(
        [
            enabled_rule,
        ]
    )

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert result.evaluated_rule_count == 1
    assert result.matched_rules == (enabled_rule,)


def test_engine_requests_rules_from_provider():
    event = create_event()

    provider = FakeRuleProvider([])

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert provider.call_count == 1
    assert result.evaluated_rule_count == 0
    assert result.matched_rules == ()


def test_engine_returns_empty_matches_when_no_rules_match():
    event = create_event()

    rule = create_rule(
        rule_id=1,
        name="Malware Detection",
        conditions={
            "event_type": "MALWARE_DETECTED",
        },
    )

    provider = FakeRuleProvider([rule])

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert result.evaluated_rule_count == 1
    assert result.matched_rules == ()


def test_engine_preserves_rule_provider_order():
    event = create_event()

    newest = create_rule(
        rule_id=3,
        name="Newest Rule",
        conditions={
            "event_type": "LOGIN_FAILED",
        },
    )

    middle = create_rule(
        rule_id=2,
        name="Middle Rule",
        conditions={
            "severity": "HIGH",
        },
    )

    oldest = create_rule(
        rule_id=1,
        name="Oldest Rule",
        conditions={
            "source": "linux",
        },
    )

    provider = FakeRuleProvider(
        [
            newest,
            middle,
            oldest,
        ]
    )

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert result.matched_rules == (
        newest,
        middle,
        oldest,
    )


def test_engine_propagates_invalid_rule_error():
    event = create_event()

    invalid_rule = create_rule(
        rule_id=1,
        name="Invalid Rule",
        conditions={
            "unsupported_field": "value",
        },
    )

    provider = FakeRuleProvider([invalid_rule])

    engine = DetectionEngine(
        rule_provider=provider,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported detection rule condition field",
    ):
        engine.evaluate_event(
            event=event,
        )


def test_engine_accepts_custom_evaluator():
    class AlwaysMatchEvaluator(RuleEvaluator):
        def evaluate(self, *, event, rule):
            from app.services.detection.rule_evaluator import (
                RuleEvaluationResult,
            )

            return RuleEvaluationResult(
                matched=True,
                rule_id=rule.id,
                event_id=event.id,
            )

    event = create_event()

    rule = create_rule(
        rule_id=1,
        name="Test Rule",
        conditions={
            "event_type": "ANYTHING",
        },
    )

    provider = FakeRuleProvider([rule])

    engine = DetectionEngine(
        rule_provider=provider,
        evaluator=AlwaysMatchEvaluator(),
    )

    result = engine.evaluate_event(
        event=event,
    )

    assert result.matched_rules == (rule,)


def test_engine_result_is_immutable():
    event = create_event()

    provider = FakeRuleProvider([])

    engine = DetectionEngine(
        rule_provider=provider,
    )

    result = engine.evaluate_event(
        event=event,
    )

    with pytest.raises(AttributeError):
        result.event_id = 9999
from app.models.detection_rule import DetectionRule
from app.services.detection.rule_provider import DetectionRuleProvider


class FakeDetectionRuleService:
    """Fake service used to isolate provider behavior."""

    def __init__(self, rules):
        self.rules = list(rules)
        self.call_count = 0

    def list_enabled_rules(self) -> list[DetectionRule]:
        self.call_count += 1
        return list(self.rules)


def create_rule(
    *,
    rule_id: int,
    name: str,
    enabled: bool = True,
) -> DetectionRule:
    return DetectionRule(
        id=rule_id,
        name=name,
        description=None,
        rule_type="TEST",
        severity="HIGH",
        conditions={"event_type": "LOGIN_FAILED"},
        enabled=enabled,
        created_by_user_id=1,
    )


def test_provider_returns_enabled_rules_from_service():
    rules = [
        create_rule(
            rule_id=1,
            name="Rule One",
        ),
        create_rule(
            rule_id=2,
            name="Rule Two",
        ),
    ]

    service = FakeDetectionRuleService(rules)
    provider = DetectionRuleProvider(service)

    result = provider.list_enabled_rules()

    assert result == rules
    assert service.call_count == 1


def test_provider_preserves_service_order():
    rules = [
        create_rule(
            rule_id=3,
            name="Newest",
        ),
        create_rule(
            rule_id=2,
            name="Middle",
        ),
        create_rule(
            rule_id=1,
            name="Oldest",
        ),
    ]

    service = FakeDetectionRuleService(rules)
    provider = DetectionRuleProvider(service)

    result = provider.list_enabled_rules()

    assert result == rules
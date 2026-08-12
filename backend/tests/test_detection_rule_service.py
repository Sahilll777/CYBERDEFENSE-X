import pytest
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule
from app.models.user import User
from app.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
)
from app.security.password import hash_password
from app.services.detection_rule_service import (
    DetectionRuleService,
)


def create_test_user(
    db: Session,
    *,
    username: str,
    email: str,
) -> User:
    """Create a database user required by service tests."""

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(
            "StrongPassword123!"
        ),
        is_active=True,
        is_superuser=False,
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


def create_rule_payload(
    *,
    name: str = "Test Detection Rule",
) -> DetectionRuleCreate:
    """Create a reusable detection-rule payload."""

    return DetectionRuleCreate(
        name=name,
        description="Detect repeated failed logins",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
            "threshold": 5,
        },
        enabled=True,
    )


def test_create_detection_rule_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_create",
        email="service_create@example.com",
    )

    service = DetectionRuleService(db_session)

    rule = service.create_rule(
        rule=create_rule_payload(
            name="service-create-rule",
        ),
        created_by_user_id=user.id,
    )

    assert isinstance(rule, DetectionRule)
    assert rule.id is not None
    assert rule.name == "service-create-rule"
    assert rule.rule_type == "BRUTE_FORCE"
    assert rule.severity == "HIGH"
    assert rule.enabled is True
    assert rule.created_by_user_id == user.id
    assert rule.conditions == {
        "event_type": "LOGIN_FAILED",
        "threshold": 5,
    }


def test_create_detection_rule_rejects_duplicate_name(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_duplicate",
        email="service_duplicate@example.com",
    )

    service = DetectionRuleService(db_session)

    service.create_rule(
        rule=create_rule_payload(
            name="duplicate-service-rule",
        ),
        created_by_user_id=user.id,
    )

    with pytest.raises(
        ValueError,
        match="Detection rule name already exists.",
    ):
        service.create_rule(
            rule=create_rule_payload(
                name="duplicate-service-rule",
            ),
            created_by_user_id=user.id,
        )


def test_get_detection_rule_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_get",
        email="service_get@example.com",
    )

    service = DetectionRuleService(db_session)

    created_rule = service.create_rule(
        rule=create_rule_payload(
            name="service-get-rule",
        ),
        created_by_user_id=user.id,
    )

    found_rule = service.get_rule(
        rule_id=created_rule.id,
    )

    assert found_rule is not None
    assert found_rule.id == created_rule.id
    assert found_rule.name == "service-get-rule"


def test_get_unknown_detection_rule_returns_none(
    db_session: Session,
):
    service = DetectionRuleService(db_session)

    rule = service.get_rule(
        rule_id=999999999,
    )

    assert rule is None


def test_get_detection_rule_by_name_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_get_name",
        email="service_get_name@example.com",
    )

    service = DetectionRuleService(db_session)

    service.create_rule(
        rule=create_rule_payload(
            name="service-name-rule",
        ),
        created_by_user_id=user.id,
    )

    rule = service.get_rule_by_name(
        name="service-name-rule",
    )

    assert rule is not None
    assert rule.name == "service-name-rule"


def test_list_detection_rules_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_list",
        email="service_list@example.com",
    )

    service = DetectionRuleService(db_session)

    service.create_rule(
        rule=create_rule_payload(
            name="service-list-brute-force",
        ),
        created_by_user_id=user.id,
    )

    service.create_rule(
        rule=DetectionRuleCreate(
            name="service-list-malware",
            description="Detect malware",
            rule_type="MALWARE",
            severity="CRITICAL",
            conditions={
                "event_type": "MALWARE_DETECTED",
            },
            enabled=True,
        ),
        created_by_user_id=user.id,
    )

    rules = service.list_rules()

    assert len(rules) == 2


def test_list_detection_rules_supports_filters(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_filters",
        email="service_filters@example.com",
    )

    service = DetectionRuleService(db_session)

    service.create_rule(
        rule=create_rule_payload(
            name="service-filter-brute-force",
        ),
        created_by_user_id=user.id,
    )

    service.create_rule(
        rule=DetectionRuleCreate(
            name="service-filter-malware",
            description="Detect malware",
            rule_type="MALWARE",
            severity="CRITICAL",
            conditions={
                "event_type": "MALWARE_DETECTED",
            },
            enabled=False,
        ),
        created_by_user_id=user.id,
    )

    brute_force_rules = service.list_rules(
        rule_type="BRUTE_FORCE",
    )

    critical_rules = service.list_rules(
        severity="CRITICAL",
    )

    disabled_rules = service.list_rules(
        enabled=False,
    )

    assert len(brute_force_rules) == 1
    assert brute_force_rules[0].rule_type == "BRUTE_FORCE"

    assert len(critical_rules) == 1
    assert critical_rules[0].severity == "CRITICAL"

    assert len(disabled_rules) == 1
    assert disabled_rules[0].enabled is False


def test_update_detection_rule_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_update",
        email="service_update@example.com",
    )

    service = DetectionRuleService(db_session)

    created_rule = service.create_rule(
        rule=create_rule_payload(
            name="service-update-rule",
        ),
        created_by_user_id=user.id,
    )

    updated_rule = service.update_rule(
        rule_id=created_rule.id,
        updates=DetectionRuleUpdate(
            name="service-updated-rule",
            severity="CRITICAL",
            enabled=False,
        ),
    )

    assert updated_rule is not None
    assert updated_rule.name == "service-updated-rule"
    assert updated_rule.severity == "CRITICAL"
    assert updated_rule.enabled is False
    assert updated_rule.rule_type == "BRUTE_FORCE"


def test_partial_update_detection_rule_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_partial",
        email="service_partial@example.com",
    )

    service = DetectionRuleService(db_session)

    created_rule = service.create_rule(
        rule=create_rule_payload(
            name="service-partial-rule",
        ),
        created_by_user_id=user.id,
    )

    updated_rule = service.update_rule(
        rule_id=created_rule.id,
        updates=DetectionRuleUpdate(
            enabled=False,
        ),
    )

    assert updated_rule is not None
    assert updated_rule.enabled is False
    assert updated_rule.name == "service-partial-rule"
    assert updated_rule.rule_type == "BRUTE_FORCE"
    assert updated_rule.severity == "HIGH"


def test_update_detection_rule_rejects_duplicate_name(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_update_duplicate",
        email="service_update_duplicate@example.com",
    )

    service = DetectionRuleService(db_session)

    service.create_rule(
        rule=create_rule_payload(
            name="existing-rule",
        ),
        created_by_user_id=user.id,
    )

    second_rule = service.create_rule(
        rule=create_rule_payload(
            name="second-rule",
        ),
        created_by_user_id=user.id,
    )

    with pytest.raises(
        ValueError,
        match="Detection rule name already exists.",
    ):
        service.update_rule(
            rule_id=second_rule.id,
            updates=DetectionRuleUpdate(
                name="existing-rule",
            ),
        )


def test_update_unknown_detection_rule_returns_none(
    db_session: Session,
):
    service = DetectionRuleService(db_session)

    result = service.update_rule(
        rule_id=999999999,
        updates=DetectionRuleUpdate(
            enabled=False,
        ),
    )

    assert result is None


def test_delete_detection_rule_through_service(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="service_delete",
        email="service_delete@example.com",
    )

    service = DetectionRuleService(db_session)

    created_rule = service.create_rule(
        rule=create_rule_payload(
            name="service-delete-rule",
        ),
        created_by_user_id=user.id,
    )

    result = service.delete_rule(
        rule_id=created_rule.id,
    )

    assert result is True

    assert service.get_rule(
        rule_id=created_rule.id,
    ) is None


def test_delete_unknown_detection_rule_returns_false(
    db_session: Session,
):
    service = DetectionRuleService(db_session)

    result = service.delete_rule(
        rule_id=999999999,
    )

    assert result is False
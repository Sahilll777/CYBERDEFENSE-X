from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule
from app.models.user import User
from app.repositories.detection_rule_repository import (
    DetectionRuleRepository,
)
from app.security.password import hash_password


def create_test_user(
    db: Session,
    *,
    username: str,
    email: str,
) -> User:
    """Create a database user required by detection-rule tests."""

    user = User(
        username=username,
        email=email,
        password_hash=hash_password("StrongPassword123!"),
        is_active=True,
        is_superuser=False,
    )

    db.add(user)
    db.flush()
    db.refresh(user)

    return user


def create_test_rule(
    db: Session,
    *,
    name: str,
    created_by_user_id: int,
    rule_type: str = "BRUTE_FORCE",
    severity: str = "HIGH",
    enabled: bool = True,
) -> DetectionRule:
    """Create a detection rule through the repository."""

    repository = DetectionRuleRepository(db)

    return repository.create(
        name=name,
        description="Test detection rule",
        rule_type=rule_type,
        severity=severity,
        conditions={
            "event_type": "LOGIN_FAILED",
            "threshold": 5,
        },
        enabled=enabled,
        created_by_user_id=created_by_user_id,
    )


def test_create_detection_rule(db_session: Session):
    user = create_test_user(
        db_session,
        username="detection_rule_create",
        email="detection_rule_create@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    rule = repository.create(
        name="test-create-rule",
        description="Detect repeated failed logins",
        rule_type="BRUTE_FORCE",
        severity="HIGH",
        conditions={
            "event_type": "LOGIN_FAILED",
            "threshold": 5,
        },
        enabled=True,
        created_by_user_id=user.id,
    )

    assert rule.id is not None
    assert rule.name == "test-create-rule"
    assert rule.description == "Detect repeated failed logins"
    assert rule.rule_type == "BRUTE_FORCE"
    assert rule.severity == "HIGH"
    assert rule.conditions == {
        "event_type": "LOGIN_FAILED",
        "threshold": 5,
    }
    assert rule.enabled is True
    assert rule.created_by_user_id == user.id


def test_get_detection_rule_by_id(db_session: Session):
    user = create_test_user(
        db_session,
        username="detection_rule_get_id",
        email="detection_rule_get_id@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    created_rule = create_test_rule(
        db_session,
        name="test-get-by-id",
        created_by_user_id=user.id,
    )

    found_rule = repository.get_by_id(created_rule.id)

    assert found_rule is not None
    assert found_rule.id == created_rule.id
    assert found_rule.name == "test-get-by-id"


def test_get_detection_rule_by_id_returns_none_for_unknown_id(
    db_session: Session,
):
    repository = DetectionRuleRepository(db_session)

    rule = repository.get_by_id(999999999)

    assert rule is None


def test_get_detection_rule_by_name(db_session: Session):
    user = create_test_user(
        db_session,
        username="detection_rule_get_name",
        email="detection_rule_get_name@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    create_test_rule(
        db_session,
        name="test-get-by-name",
        created_by_user_id=user.id,
    )

    rule = repository.get_by_name("test-get-by-name")

    assert rule is not None
    assert rule.name == "test-get-by-name"


def test_get_detection_rule_by_name_returns_none_for_unknown_name(
    db_session: Session,
):
    repository = DetectionRuleRepository(db_session)

    rule = repository.get_by_name("does-not-exist")

    assert rule is None


def test_list_detection_rules_returns_newest_first(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection_rule_list",
        email="detection_rule_list@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    first = create_test_rule(
        db_session,
        name="test-list-first",
        created_by_user_id=user.id,
    )

    second = create_test_rule(
        db_session,
        name="test-list-second",
        created_by_user_id=user.id,
    )

    rules = repository.list_rules()

    rule_ids = [rule.id for rule in rules]

    assert second.id in rule_ids
    assert first.id in rule_ids
    assert rule_ids.index(second.id) < rule_ids.index(first.id)


def test_list_detection_rules_supports_rule_type_filter(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection_rule_type",
        email="detection_rule_type@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    create_test_rule(
        db_session,
        name="test-rule-type-brute-force",
        created_by_user_id=user.id,
        rule_type="BRUTE_FORCE",
    )

    create_test_rule(
        db_session,
        name="test-rule-type-malware",
        created_by_user_id=user.id,
        rule_type="MALWARE",
    )

    rules = repository.list_rules(
        rule_type="BRUTE_FORCE",
    )

    assert len(rules) == 1
    assert rules[0].rule_type == "BRUTE_FORCE"


def test_list_detection_rules_supports_severity_filter(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection_rule_severity",
        email="detection_rule_severity@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    create_test_rule(
        db_session,
        name="test-severity-high",
        created_by_user_id=user.id,
        severity="HIGH",
    )

    create_test_rule(
        db_session,
        name="test-severity-critical",
        created_by_user_id=user.id,
        severity="CRITICAL",
    )

    rules = repository.list_rules(
        severity="CRITICAL",
    )

    assert len(rules) == 1
    assert rules[0].severity == "CRITICAL"


def test_list_detection_rules_supports_enabled_filter(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection_rule_enabled",
        email="detection_rule_enabled@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    create_test_rule(
        db_session,
        name="test-enabled-rule",
        created_by_user_id=user.id,
        enabled=True,
    )

    create_test_rule(
        db_session,
        name="test-disabled-rule",
        created_by_user_id=user.id,
        enabled=False,
    )

    rules = repository.list_rules(
        enabled=False,
    )

    assert len(rules) == 1
    assert rules[0].name == "test-disabled-rule"
    assert rules[0].enabled is False


def test_list_detection_rules_supports_creator_filter(
    db_session: Session,
):
    first_user = create_test_user(
        db_session,
        username="detection_rule_creator_one",
        email="detection_rule_creator_one@example.com",
    )

    second_user = create_test_user(
        db_session,
        username="detection_rule_creator_two",
        email="detection_rule_creator_two@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    create_test_rule(
        db_session,
        name="test-creator-one",
        created_by_user_id=first_user.id,
    )

    create_test_rule(
        db_session,
        name="test-creator-two",
        created_by_user_id=second_user.id,
    )

    rules = repository.list_rules(
        created_by_user_id=second_user.id,
    )

    assert len(rules) == 1
    assert rules[0].created_by_user_id == second_user.id


def test_list_detection_rules_supports_pagination(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection_rule_pagination",
        email="detection_rule_pagination@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    create_test_rule(
        db_session,
        name="test-pagination-one",
        created_by_user_id=user.id,
    )

    create_test_rule(
        db_session,
        name="test-pagination-two",
        created_by_user_id=user.id,
    )

    create_test_rule(
        db_session,
        name="test-pagination-three",
        created_by_user_id=user.id,
    )

    rules = repository.list_rules(
        limit=2,
        offset=1,
    )

    assert len(rules) == 2


def test_update_detection_rule(db_session: Session):
    user = create_test_user(
        db_session,
        username="detection_rule_update",
        email="detection_rule_update@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    rule = create_test_rule(
        db_session,
        name="test-update",
        created_by_user_id=user.id,
    )

    updated_rule = repository.update(
        rule,
        name="test-update-renamed",
        description="Updated description",
        rule_type="SUSPICIOUS_LOGIN",
        severity="CRITICAL",
        conditions={
            "event_type": "LOGIN_FAILED",
            "threshold": 10,
        },
        enabled=False,
    )

    assert updated_rule.name == "test-update-renamed"
    assert updated_rule.description == "Updated description"
    assert updated_rule.rule_type == "SUSPICIOUS_LOGIN"
    assert updated_rule.severity == "CRITICAL"
    assert updated_rule.conditions == {
        "event_type": "LOGIN_FAILED",
        "threshold": 10,
    }
    assert updated_rule.enabled is False


def test_update_detection_rule_supports_partial_update(
    db_session: Session,
):
    user = create_test_user(
        db_session,
        username="detection_rule_partial",
        email="detection_rule_partial@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    rule = create_test_rule(
        db_session,
        name="test-partial-update",
        created_by_user_id=user.id,
        severity="HIGH",
    )

    updated_rule = repository.update(
        rule,
        enabled=False,
    )

    assert updated_rule.name == "test-partial-update"
    assert updated_rule.severity == "HIGH"
    assert updated_rule.enabled is False


def test_delete_detection_rule(db_session: Session):
    user = create_test_user(
        db_session,
        username="detection_rule_delete",
        email="detection_rule_delete@example.com",
    )

    repository = DetectionRuleRepository(db_session)

    rule = create_test_rule(
        db_session,
        name="test-delete",
        created_by_user_id=user.id,
    )

    rule_id = rule.id

    repository.delete(rule)
    db_session.commit()

    deleted_rule = repository.get_by_id(rule_id)

    assert deleted_rule is None
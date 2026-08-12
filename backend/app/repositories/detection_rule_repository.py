from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule


class DetectionRuleRepository:
    """Database access operations for DetectionRule entities."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        *,
        name: str,
        description: str | None,
        rule_type: str,
        severity: str,
        conditions: dict[str, Any],
        enabled: bool,
        created_by_user_id: int,
    ) -> DetectionRule:
        """Create and persist a detection rule."""

        rule = DetectionRule(
            name=name,
            description=description,
            rule_type=rule_type,
            severity=severity,
            conditions=conditions,
            enabled=enabled,
            created_by_user_id=created_by_user_id,
        )

        self.db.add(rule)
        self.db.flush()
        self.db.refresh(rule)

        return rule

    def get_by_id(
        self,
        rule_id: int,
    ) -> DetectionRule | None:
        """Return a detection rule by its primary key."""

        statement = select(DetectionRule).where(
            DetectionRule.id == rule_id
        )

        return self.db.scalar(statement)

    def get_by_name(
        self,
        name: str,
    ) -> DetectionRule | None:
        """Return a detection rule by its unique name."""

        statement = select(DetectionRule).where(
            DetectionRule.name == name
        )

        return self.db.scalar(statement)

    def list_rules(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        rule_type: str | None = None,
        severity: str | None = None,
        enabled: bool | None = None,
        created_by_user_id: int | None = None,
    ) -> list[DetectionRule]:
        """Return detection rules with optional filters."""

        statement = select(DetectionRule)

        if rule_type is not None:
            statement = statement.where(
                DetectionRule.rule_type == rule_type
            )

        if severity is not None:
            statement = statement.where(
                DetectionRule.severity == severity
            )

        if enabled is not None:
            statement = statement.where(
                DetectionRule.enabled == enabled
            )

        if created_by_user_id is not None:
            statement = statement.where(
                DetectionRule.created_by_user_id == created_by_user_id
            )

        statement = (
            statement
            .order_by(
                DetectionRule.created_at.desc(),
                DetectionRule.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(self.db.scalars(statement).all())

    def list_enabled_rules(self) -> list[DetectionRule]:
        """
        Return all enabled detection rules in deterministic order.

        This method intentionally does not use API pagination because
        the detection engine must evaluate every enabled rule.
        """

        statement = (
            select(DetectionRule)
            .where(DetectionRule.enabled.is_(True))
            .order_by(
                DetectionRule.created_at.desc(),
                DetectionRule.id.desc(),
            )
        )

        return list(self.db.scalars(statement).all())

    def update(
        self,
        rule: DetectionRule,
        *,
        name: str | None = None,
        description: str | None = None,
        rule_type: str | None = None,
        severity: str | None = None,
        conditions: dict[str, Any] | None = None,
        enabled: bool | None = None,
    ) -> DetectionRule:
        """Update a detection rule using only supplied values."""

        if name is not None:
            rule.name = name

        if description is not None:
            rule.description = description

        if rule_type is not None:
            rule.rule_type = rule_type

        if severity is not None:
            rule.severity = severity

        if conditions is not None:
            rule.conditions = conditions

        if enabled is not None:
            rule.enabled = enabled

        self.db.add(rule)
        self.db.flush()
        self.db.refresh(rule)

        return rule

    def delete(
        self,
        rule: DetectionRule,
    ) -> None:
        """Delete a detection rule."""

        self.db.delete(rule)
        self.db.flush()
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule
from app.repositories.detection_rule_repository import (
    DetectionRuleRepository,
)
from app.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
)


class DetectionRuleService:
    """Business logic for detection rule management."""

    def __init__(self, db: Session):
        self.detection_rule_repository = DetectionRuleRepository(db)

    def create_rule(
        self,
        *,
        rule: DetectionRuleCreate,
        created_by_user_id: int,
    ) -> DetectionRule:
        """Create a detection rule."""

        existing_rule = self.detection_rule_repository.get_by_name(
            rule.name
        )

        if existing_rule is not None:
            raise ValueError(
                "Detection rule name already exists."
            )

        return self.detection_rule_repository.create(
            name=rule.name,
            description=rule.description,
            rule_type=rule.rule_type,
            severity=rule.severity,
            conditions=rule.conditions,
            enabled=rule.enabled,
            created_by_user_id=created_by_user_id,
        )

    def get_rule(
        self,
        *,
        rule_id: int,
    ) -> DetectionRule | None:
        """Retrieve a detection rule by ID."""

        return self.detection_rule_repository.get_by_id(
            rule_id
        )

    def get_rule_by_name(
        self,
        *,
        name: str,
    ) -> DetectionRule | None:
        """Retrieve a detection rule by its unique name."""

        return self.detection_rule_repository.get_by_name(
            name
        )

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
        """Retrieve detection rules using repository filters."""

        return self.detection_rule_repository.list_rules(
            limit=limit,
            offset=offset,
            rule_type=rule_type,
            severity=severity,
            enabled=enabled,
            created_by_user_id=created_by_user_id,
        )

    def list_enabled_rules(self) -> list[DetectionRule]:
        """
        Retrieve every enabled detection rule for the detection engine.

        This intentionally bypasses API pagination.
        """

        return self.detection_rule_repository.list_enabled_rules()

    def update_rule(
        self,
        *,
        rule_id: int,
        updates: DetectionRuleUpdate,
    ) -> DetectionRule | None:
        """Update a detection rule using supplied fields only."""

        rule = self.detection_rule_repository.get_by_id(
            rule_id
        )

        if rule is None:
            return None

        update_data = updates.model_dump(
            exclude_unset=True,
        )

        if "name" in update_data:
            existing_rule = (
                self.detection_rule_repository.get_by_name(
                    update_data["name"]
                )
            )

            if (
                existing_rule is not None
                and existing_rule.id != rule.id
            ):
                raise ValueError(
                    "Detection rule name already exists."
                )

        return self.detection_rule_repository.update(
            rule,
            **update_data,
        )

    def delete_rule(
        self,
        *,
        rule_id: int,
    ) -> bool:
        """Delete a detection rule.

        Returns True when the rule existed and was deleted,
        otherwise returns False.
        """

        rule = self.detection_rule_repository.get_by_id(
            rule_id
        )

        if rule is None:
            return False

        self.detection_rule_repository.delete(rule)

        return True
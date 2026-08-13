from __future__ import annotations

from app.models.detection_rule import DetectionRule
from app.services.detection_rule_service import DetectionRuleService


class DetectionRuleProvider:
    """Provide detection rules to the detection engine."""

    def __init__(
        self,
        detection_rule_service: DetectionRuleService,
    ):
        self.detection_rule_service = detection_rule_service

    def list_enabled_rules(self) -> list[DetectionRule]:
        """Return every enabled detection rule for evaluation."""

        return self.detection_rule_service.list_enabled_rules()
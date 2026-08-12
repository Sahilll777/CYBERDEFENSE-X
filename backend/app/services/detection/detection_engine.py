from __future__ import annotations

from dataclasses import dataclass

from app.models.detection_rule import DetectionRule
from app.models.security_event import SecurityEvent
from app.services.detection.rule_evaluator import (
    RuleEvaluationResult,
    RuleEvaluator,
)


@dataclass(frozen=True)
class DetectionEngineResult:
    """Result of evaluating one security event against detection rules."""

    event_id: int
    evaluated_rule_count: int
    matched_rules: tuple[DetectionRule, ...]


class DetectionEngine:
    """
    Evaluate security events against enabled detection rules.

    The engine is intentionally independent from FastAPI and database
    session management. Rule retrieval is delegated to the supplied
    rule provider.
    """

    def __init__(
        self,
        *,
        rule_provider,
        evaluator: RuleEvaluator | None = None,
    ):
        self.rule_provider = rule_provider
        self.evaluator = evaluator or RuleEvaluator()

    def evaluate_event(
        self,
        *,
        event: SecurityEvent,
    ) -> DetectionEngineResult:
        """
        Evaluate one security event against every enabled rule.

        Rules are evaluated in the deterministic order supplied by the
        rule provider.
        """

        rules = self.rule_provider.list_enabled_rules()

        matched_rules: list[DetectionRule] = []

        for rule in rules:
            evaluation: RuleEvaluationResult = (
                self.evaluator.evaluate(
                    event=event,
                    rule=rule,
                )
            )

            if evaluation.matched:
                matched_rules.append(rule)

        return DetectionEngineResult(
            event_id=event.id,
            evaluated_rule_count=len(rules),
            matched_rules=tuple(matched_rules),
        )
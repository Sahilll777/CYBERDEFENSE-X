from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.detection_rule import DetectionRule
from app.models.security_event import SecurityEvent


@dataclass(frozen=True)
class RuleEvaluationResult:
    """Result of evaluating one detection rule against one security event."""

    matched: bool
    rule_id: int
    event_id: int


class RuleEvaluator:
    """
    Evaluate a DetectionRule against a single SecurityEvent.

    Version 1 supports exact equality matching across a controlled set
    of security-event fields.

    All supplied conditions use AND semantics.
    """

    SUPPORTED_FIELDS = frozenset(
        {
            "event_type",
            "severity",
            "source",
            "source_ip",
            "destination_ip",
            "username",
            "hostname",
            "message",
        }
    )

    def evaluate(
        self,
        *,
        event: SecurityEvent,
        rule: DetectionRule,
    ) -> RuleEvaluationResult:
        """
        Evaluate one detection rule against one security event.

        Returns a deterministic evaluation result.

        Raises:
            ValueError:
                If the rule contains unsupported fields, invalid condition
                values, or no conditions.
        """

        if not rule.enabled:
            return RuleEvaluationResult(
                matched=False,
                rule_id=rule.id,
                event_id=event.id,
            )

        conditions = rule.conditions

        if not isinstance(conditions, dict):
            raise ValueError(
                "Detection rule conditions must be a JSON object."
            )

        if not conditions:
            raise ValueError(
                "Detection rule must contain at least one condition."
            )

        self._validate_conditions(conditions)

        for field_name, expected_value in conditions.items():
            actual_value = getattr(event, field_name)

            if not self._values_equal(
                actual_value,
                expected_value,
            ):
                return RuleEvaluationResult(
                    matched=False,
                    rule_id=rule.id,
                    event_id=event.id,
                )

        return RuleEvaluationResult(
            matched=True,
            rule_id=rule.id,
            event_id=event.id,
        )

    @classmethod
    def _validate_conditions(
        cls,
        conditions: dict[str, Any],
    ) -> None:
        """Validate that all supplied rule conditions are supported."""

        unsupported_fields = set(conditions) - cls.SUPPORTED_FIELDS

        if unsupported_fields:
            fields = ", ".join(sorted(unsupported_fields))

            raise ValueError(
                f"Unsupported detection rule condition field(s): {fields}"
            )

        for field_name, expected_value in conditions.items():
            if isinstance(expected_value, (dict, list, tuple, set)):
                raise ValueError(
                    f"Condition value for '{field_name}' must be a scalar."
                )

    @staticmethod
    def _values_equal(
        actual_value: Any,
        expected_value: Any,
    ) -> bool:
        """
        Compare an event value with a rule condition value.

        String comparisons are case-insensitive after trimming surrounding
        whitespace. Non-string values use normal equality semantics.
        """

        if actual_value is None or expected_value is None:
            return actual_value is expected_value

        if isinstance(actual_value, str) and isinstance(
            expected_value,
            str,
        ):
            return (
                actual_value.strip().casefold()
                == expected_value.strip().casefold()
            )

        return actual_value == expected_value
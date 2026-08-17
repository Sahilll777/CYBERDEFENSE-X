from typing import Any

from app.services.playbook_execution.handlers.base import (
    PlaybookActionHandler,
)


class CreateIncidentHandler(PlaybookActionHandler):
    """
    Handle incident-creation actions.

    Actual incident persistence will be integrated through the
    existing IncidentService in the appropriate execution phase.
    """

    action_type = "CREATE_INCIDENT"

    def execute(
        self,
        *,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate and accept an incident-creation request."""

        severity = parameters.get(
            "severity",
            "MEDIUM",
        )

        if not isinstance(severity, str):
            raise ValueError(
                "CREATE_INCIDENT 'severity' must be a string."
            )

        severity = severity.strip().upper()

        if not severity:
            raise ValueError(
                "CREATE_INCIDENT 'severity' "
                "cannot be empty."
            )

        return {
            "action": self.action_type,
            "status": "SUCCESS",
            "message": (
                "Incident creation action accepted "
                "for execution."
            ),
            "data": {
                "severity": severity,
            },
        }
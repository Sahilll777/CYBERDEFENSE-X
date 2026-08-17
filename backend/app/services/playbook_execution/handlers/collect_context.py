from typing import Any

from app.services.playbook_execution.handlers.base import (
    PlaybookActionHandler,
)


class CollectContextHandler(PlaybookActionHandler):
    """Collect contextual information for a playbook execution."""

    action_type = "COLLECT_CONTEXT"

    def execute(
        self,
        *,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the currently available execution context."""

        source = parameters.get(
            "source",
            "execution",
        )

        return {
            "action": self.action_type,
            "status": "SUCCESS",
            "message": "Execution context collected successfully.",
            "data": {
                "source": source,
                "context": context.copy(),
            },
        }
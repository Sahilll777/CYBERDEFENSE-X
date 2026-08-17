from typing import Any

from app.services.playbook_execution.handlers.base import (
    PlaybookActionHandler,
)


class BlockSourceHandler(PlaybookActionHandler):
    """
    Handle a source-blocking action.

    This handler currently performs no real network blocking.
    It validates and records the requested containment action so
    that a real firewall/EDR integration can be added later.
    """

    action_type = "BLOCK_SOURCE"

    def execute(
        self,
        *,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate and accept a source-blocking request."""

        target = parameters.get("target")

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "BLOCK_SOURCE requires a non-empty "
                "'target' parameter."
            )

        target = target.strip()

        return {
            "action": self.action_type,
            "status": "SUCCESS",
            "message": (
                "Source blocking action accepted "
                "for execution."
            ),
            "data": {
                "target": target,
            },
        }
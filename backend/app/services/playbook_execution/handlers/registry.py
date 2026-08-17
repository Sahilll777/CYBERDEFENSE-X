from typing import Any

from app.services.playbook_execution.handlers.base import (
    PlaybookActionHandler,
)


class PlaybookActionRegistry:
    """Registry responsible for resolving playbook action handlers."""

    def __init__(
        self,
        handlers: list[PlaybookActionHandler],
    ) -> None:
        self._handlers = {
            handler.action_type: handler
            for handler in handlers
        }

    def get(
        self,
        action_type: str,
    ) -> PlaybookActionHandler | None:
        """Return the handler registered for an action type."""

        return self._handlers.get(action_type)

    def supported_actions(self) -> list[str]:
        """Return supported action types."""

        return sorted(self._handlers.keys())

    def execute(
        self,
        *,
        action_type: str,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Resolve and execute an action handler."""

        handler = self.get(action_type)

        if handler is None:
            raise ValueError(
                f"Unsupported playbook action type: "
                f"{action_type}."
            )

        return handler.execute(
            parameters=parameters,
            context=context,
        )
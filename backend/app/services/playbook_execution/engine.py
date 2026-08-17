from typing import Any

from app.models.playbook import Playbook
from app.services.playbook_execution.handlers import (
    BlockSourceHandler,
    CollectContextHandler,
    CreateIncidentHandler,
    PlaybookActionHandler,
    PlaybookActionRegistry,
)


class PlaybookExecutionEngine:
    """
    Execute the action definition of a security playbook.

    The engine is responsible only for interpreting and dispatching
    playbook actions. Execution lifecycle state is managed by
    PlaybookExecutionService.
    """

    def __init__(
        self,
        *,
        handlers: list[PlaybookActionHandler] | None = None,
    ) -> None:
        if handlers is None:
            handlers = [
                CollectContextHandler(),
                BlockSourceHandler(),
                CreateIncidentHandler(),
            ]

        self.registry = PlaybookActionRegistry(
            handlers
        )

    def execute(
        self,
        *,
        playbook: Playbook,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute all actions defined by a playbook.

        Actions are executed sequentially in the order in which
        they appear in the playbook definition.
        """

        if not playbook.enabled:
            raise ValueError(
                f"Playbook '{playbook.name}' is disabled."
            )

        actions = self._extract_actions(
            playbook.definition
        )

        execution_context = (
            context.copy()
            if context is not None
            else {}
        )

        results: list[dict[str, Any]] = []

        for index, action in enumerate(actions):
            action_type = action["type"]
            parameters = action["parameters"]

            result = self.registry.execute(
                action_type=action_type,
                parameters=parameters,
                context=execution_context,
            )

            results.append(
                {
                    "index": index,
                    "type": action_type,
                    "status": result.get(
                        "status",
                        "SUCCESS",
                    ),
                    "result": result,
                }
            )

        return results

    def supported_actions(self) -> list[str]:
        """Return all registered action types."""

        return self.registry.supported_actions()

    @staticmethod
    def _extract_actions(
        definition: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Validate and extract actions from a playbook definition."""

        if not isinstance(definition, dict):
            raise ValueError(
                "Playbook definition must be an object."
            )

        actions = definition.get("actions")

        if not isinstance(actions, list):
            raise ValueError(
                "Playbook definition must contain "
                "an 'actions' list."
            )

        normalized_actions: list[dict[str, Any]] = []

        for index, action in enumerate(actions):
            if not isinstance(action, dict):
                raise ValueError(
                    f"Playbook action at index {index} "
                    "must be an object."
                )

            action_type = action.get("type")

            if not isinstance(action_type, str):
                raise ValueError(
                    f"Playbook action at index {index} "
                    "must contain a string 'type'."
                )

            action_type = action_type.strip()

            if not action_type:
                raise ValueError(
                    f"Playbook action at index {index} "
                    "has an empty action type."
                )

            parameters = action.get(
                "parameters",
                {},
            )

            if not isinstance(parameters, dict):
                raise ValueError(
                    f"Parameters for playbook action "
                    f"at index {index} must be an object."
                )

            normalized_actions.append(
                {
                    "type": action_type,
                    "parameters": parameters,
                }
            )

        return normalized_actions
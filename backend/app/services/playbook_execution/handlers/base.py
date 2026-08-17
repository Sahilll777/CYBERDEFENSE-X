from abc import ABC, abstractmethod
from typing import Any


class PlaybookActionHandler(ABC):
    """Base interface for playbook action handlers."""

    action_type: str

    @abstractmethod
    def execute(
        self,
        *,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute a single playbook action.

        Handlers must return a structured result and must not
        directly control the playbook execution lifecycle.
        """
        raise NotImplementedError
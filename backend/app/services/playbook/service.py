from sqlalchemy.orm import Session

from app.models.playbook import Playbook
from app.repositories.playbook.playbook_repository import (
    PlaybookRepository,
)


class PlaybookService:
    """Business logic for security playbook management."""

    def __init__(self, db: Session):
        self.playbook_repository = PlaybookRepository(db)

    def create_playbook(
        self,
        *,
        name: str,
        description: str | None,
        playbook_type: str,
        version: int,
        enabled: bool,
        definition: dict,
        created_by_user_id: int,
    ) -> Playbook:
        """
        Create a new playbook.

        Playbook names must be unique.
        """

        existing_playbook = (
            self.playbook_repository.get_by_name(name)
        )

        if existing_playbook is not None:
            raise ValueError(
                f"Playbook with name '{name}' already exists."
            )

        return self.playbook_repository.create(
            name=name,
            description=description,
            playbook_type=playbook_type,
            version=version,
            enabled=enabled,
            definition=definition,
            created_by_user_id=created_by_user_id,
        )

    def get_playbook(
        self,
        *,
        playbook_id: int,
    ) -> Playbook | None:
        """Retrieve a playbook by ID."""

        return self.playbook_repository.get_by_id(
            playbook_id
        )

    def get_playbook_by_name(
        self,
        *,
        name: str,
    ) -> Playbook | None:
        """Retrieve a playbook by name."""

        return self.playbook_repository.get_by_name(
            name
        )

    def list_playbooks(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        playbook_type: str | None = None,
        enabled: bool | None = None,
        created_by_user_id: int | None = None,
    ) -> list[Playbook]:
        """Retrieve playbooks using repository filters."""

        return self.playbook_repository.list_playbooks(
            limit=limit,
            offset=offset,
            playbook_type=playbook_type,
            enabled=enabled,
            created_by_user_id=created_by_user_id,
        )

    def update_playbook(
        self,
        *,
        playbook_id: int,
        name: str | None = None,
        description: str | None = None,
        playbook_type: str | None = None,
        version: int | None = None,
        enabled: bool | None = None,
        definition: dict | None = None,
    ) -> Playbook | None:
        """Update an existing playbook."""

        playbook = self.playbook_repository.get_by_id(
            playbook_id
        )

        if playbook is None:
            return None

        if (
            name is not None
            and name != playbook.name
        ):
            existing_playbook = (
                self.playbook_repository.get_by_name(name)
            )

            if existing_playbook is not None:
                raise ValueError(
                    f"Playbook with name '{name}' already exists."
                )

        return self.playbook_repository.update(
            playbook,
            name=name,
            description=description,
            playbook_type=playbook_type,
            version=version,
            enabled=enabled,
            definition=definition,
        )

    def enable_playbook(
        self,
        *,
        playbook_id: int,
    ) -> Playbook | None:
        """Enable a playbook."""

        return self.update_playbook(
            playbook_id=playbook_id,
            enabled=True,
        )

    def disable_playbook(
        self,
        *,
        playbook_id: int,
    ) -> Playbook | None:
        """Disable a playbook."""

        return self.update_playbook(
            playbook_id=playbook_id,
            enabled=False,
        )
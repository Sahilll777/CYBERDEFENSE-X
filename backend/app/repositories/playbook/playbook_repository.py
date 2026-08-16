from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.playbook import Playbook


class PlaybookRepository:
    """Database access operations for Playbook entities."""

    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        *,
        name: str,
        description: str | None,
        playbook_type: str,
        version: int = 1,
        enabled: bool = True,
        definition: dict,
        created_by_user_id: int,
    ) -> Playbook:
        """Create and persist a playbook."""

        playbook = Playbook(
            name=name,
            description=description,
            playbook_type=playbook_type,
            version=version,
            enabled=enabled,
            definition=definition,
            created_by_user_id=created_by_user_id,
        )

        self.db.add(playbook)
        self.db.flush()
        self.db.refresh(playbook)

        return playbook

    def get_by_id(
        self,
        playbook_id: int,
    ) -> Playbook | None:
        """Return a playbook by primary key."""

        statement = select(Playbook).where(
            Playbook.id == playbook_id
        )

        return self.db.scalar(statement)

    def get_by_name(
        self,
        name: str,
    ) -> Playbook | None:
        """Return a playbook by its unique name."""

        statement = select(Playbook).where(
            Playbook.name == name
        )

        return self.db.scalar(statement)

    def list_playbooks(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        playbook_type: str | None = None,
        enabled: bool | None = None,
        created_by_user_id: int | None = None,
    ) -> list[Playbook]:
        """Return playbooks with optional filters."""

        statement = select(Playbook)

        if playbook_type is not None:
            statement = statement.where(
                Playbook.playbook_type == playbook_type
            )

        if enabled is not None:
            statement = statement.where(
                Playbook.enabled == enabled
            )

        if created_by_user_id is not None:
            statement = statement.where(
                Playbook.created_by_user_id
                == created_by_user_id
            )

        statement = (
            statement
            .order_by(
                Playbook.created_at.desc(),
                Playbook.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(
            self.db.scalars(statement).all()
        )

    def update(
        self,
        playbook: Playbook,
        *,
        name: str | None = None,
        description: str | None = None,
        playbook_type: str | None = None,
        version: int | None = None,
        enabled: bool | None = None,
        definition: dict | None = None,
    ) -> Playbook:
        """Update mutable playbook fields."""

        if name is not None:
            playbook.name = name

        if description is not None:
            playbook.description = description

        if playbook_type is not None:
            playbook.playbook_type = playbook_type

        if version is not None:
            playbook.version = version

        if enabled is not None:
            playbook.enabled = enabled

        if definition is not None:
            playbook.definition = definition

        self.db.add(playbook)
        self.db.flush()
        self.db.refresh(playbook)

        return playbook
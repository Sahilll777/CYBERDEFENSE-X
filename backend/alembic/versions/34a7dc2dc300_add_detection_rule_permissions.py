"""add detection rule permissions

Revision ID: 34a7dc2dc300
Revises: 61742ffcebb0
Create Date: 2026-08-12 19:24:16.157630

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "34a7dc2dc300"
down_revision: Union[str, Sequence[str], None] = "61742ffcebb0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PERMISSIONS = [
    (
        "detection_rules.read",
        "Read detection rules",
    ),
    (
        "detection_rules.create",
        "Create detection rules",
    ),
    (
        "detection_rules.update",
        "Update detection rules",
    ),
    (
        "detection_rules.delete",
        "Delete detection rules",
    ),
]


ROLE_PERMISSIONS = {
    "SOC_ANALYST": [
        "detection_rules.read",
    ],
    "SOC_MANAGER": [
        "detection_rules.read",
        "detection_rules.create",
        "detection_rules.update",
        "detection_rules.delete",
    ],
    "SECURITY_ADMIN": [
        "detection_rules.read",
        "detection_rules.create",
        "detection_rules.update",
        "detection_rules.delete",
    ],
}


def upgrade() -> None:
    """Add detection rule permissions and role mappings."""

    connection = op.get_bind()

    # ---------------------------------------------------------
    # Create permissions
    # ---------------------------------------------------------
    permission_ids: dict[str, int] = {}

    for permission_name, description in PERMISSIONS:
        existing_permission = connection.execute(
            sa.text(
                """
                SELECT id
                FROM permissions
                WHERE name = :name
                """
            ),
            {"name": permission_name},
        ).scalar_one_or_none()

        if existing_permission is None:
            permission_id = connection.execute(
                sa.text(
                    """
                    INSERT INTO permissions (name, description)
                    VALUES (:name, :description)
                    RETURNING id
                    """
                ),
                {
                    "name": permission_name,
                    "description": description,
                },
            ).scalar_one()
        else:
            permission_id = existing_permission

        permission_ids[permission_name] = permission_id

    # ---------------------------------------------------------
    # Create role-permission mappings
    # ---------------------------------------------------------
    for role_name, permission_names in ROLE_PERMISSIONS.items():
        role_id = connection.execute(
            sa.text(
                """
                SELECT id
                FROM roles
                WHERE name = :name
                """
            ),
            {"name": role_name},
        ).scalar_one_or_none()

        if role_id is None:
            raise RuntimeError(
                f"Required RBAC role does not exist: {role_name}"
            )

        for permission_name in permission_names:
            permission_id = permission_ids[permission_name]

            existing_mapping = connection.execute(
                sa.text(
                    """
                    SELECT 1
                    FROM role_permissions
                    WHERE role_id = :role_id
                      AND permission_id = :permission_id
                    """
                ),
                {
                    "role_id": role_id,
                    "permission_id": permission_id,
                },
            ).scalar_one_or_none()

            if existing_mapping is None:
                connection.execute(
                    sa.text(
                        """
                        INSERT INTO role_permissions (
                            role_id,
                            permission_id
                        )
                        VALUES (
                            :role_id,
                            :permission_id
                        )
                        """
                    ),
                    {
                        "role_id": role_id,
                        "permission_id": permission_id,
                    },
                )


def downgrade() -> None:
    """Remove detection rule permissions and role mappings."""

    connection = op.get_bind()

    permission_names = [
        permission_name
        for permission_name, _ in PERMISSIONS
    ]

    # ---------------------------------------------------------
    # Remove role-permission mappings
    # ---------------------------------------------------------
    connection.execute(
        sa.text(
            """
            DELETE FROM role_permissions
            WHERE permission_id IN (
                SELECT id
                FROM permissions
                WHERE name = ANY(:permission_names)
            )
            """
        ),
        {
            "permission_names": permission_names,
        },
    )

    # ---------------------------------------------------------
    # Remove permissions
    # ---------------------------------------------------------
    connection.execute(
        sa.text(
            """
            DELETE FROM permissions
            WHERE name = ANY(:permission_names)
            """
        ),
        {
            "permission_names": permission_names,
        },
    )
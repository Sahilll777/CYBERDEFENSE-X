"""add alert permissions

Revision ID: 0d22d9e057db
Revises: c01134cc5b8a
Create Date: 2026-08-14 15:31:39.744773

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0d22d9e057db"
down_revision: Union[str, Sequence[str], None] = "c01134cc5b8a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PERMISSIONS = [
    (
        "alerts.read",
        "Read security alerts",
    ),
    (
        "alerts.update",
        "Update security alert status",
    ),
    (
        "alerts.assign",
        "Assign security alerts to users",
    ),
]


ROLE_PERMISSION_MAP = {
    "SECURITY_ADMIN": {
        "alerts.read",
        "alerts.update",
        "alerts.assign",
    },
    "SOC_MANAGER": {
        "alerts.read",
        "alerts.update",
        "alerts.assign",
    },
    "SOC_ANALYST": {
        "alerts.read",
        "alerts.update",
    },
}


def upgrade() -> None:
    """Add alert permissions and assign them to appropriate roles."""

    connection = op.get_bind()

    permissions_table = sa.table(
        "permissions",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )

    roles_table = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
    )

    role_permissions_table = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )

    # ------------------------------------------------------------------
    # Create permissions
    # ------------------------------------------------------------------

    for permission_name, description in PERMISSIONS:
        existing_permission = connection.execute(
            sa.select(permissions_table.c.id).where(
                permissions_table.c.name == permission_name
            )
        ).scalar_one_or_none()

        if existing_permission is None:
            connection.execute(
                permissions_table.insert().values(
                    name=permission_name,
                    description=description,
                )
            )

    # ------------------------------------------------------------------
    # Assign permissions to roles
    # ------------------------------------------------------------------

    for role_name, permission_names in ROLE_PERMISSION_MAP.items():
        role_id = connection.execute(
            sa.select(roles_table.c.id).where(
                roles_table.c.name == role_name
            )
        ).scalar_one_or_none()

        if role_id is None:
            continue

        for permission_name in permission_names:
            permission_id = connection.execute(
                sa.select(permissions_table.c.id).where(
                    permissions_table.c.name == permission_name
                )
            ).scalar_one()

            existing_assignment = connection.execute(
                sa.select(
                    role_permissions_table.c.role_id
                ).where(
                    role_permissions_table.c.role_id == role_id,
                    role_permissions_table.c.permission_id == permission_id,
                )
            ).scalar_one_or_none()

            if existing_assignment is None:
                connection.execute(
                    role_permissions_table.insert().values(
                        role_id=role_id,
                        permission_id=permission_id,
                    )
                )


def downgrade() -> None:
    """Remove alert permissions and their role assignments."""

    connection = op.get_bind()

    permissions_table = sa.table(
        "permissions",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )

    roles_table = sa.table(
        "roles",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
    )

    role_permissions_table = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )

    permission_names = [
        permission_name
        for permission_name, _ in PERMISSIONS
    ]

    permission_rows = connection.execute(
        sa.select(
            permissions_table.c.id,
            permissions_table.c.name,
        ).where(
            permissions_table.c.name.in_(permission_names)
        )
    ).fetchall()

    for permission_id, permission_name in permission_rows:
        connection.execute(
            role_permissions_table.delete().where(
                role_permissions_table.c.permission_id == permission_id
            )
        )

        connection.execute(
            permissions_table.delete().where(
                permissions_table.c.id == permission_id
            )
        )
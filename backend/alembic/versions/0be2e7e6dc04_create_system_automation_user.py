"""create system automation user

Revision ID: 0be2e7e6dc04
Revises: f13a57a9629d
Create Date: 2026-08-18
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# Revision identifiers, used by Alembic.
revision: str = "0be2e7e6dc04"
down_revision: Union[str, Sequence[str], None] = "f13a57a9629d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SYSTEM_USERNAME = "system"
SYSTEM_EMAIL = "system@cyberdefense-x.local"

# This is an intentionally unusable credential for the inactive
# automation principal. The account is created with is_active = false,
# so the normal authentication flow will reject it before the password
# can be used.
SYSTEM_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$"
    "c3lzdGVtLWF1dG9tYXRpb24="
    "$"
    "c3lzdGVtLWF1dG9tYXRpb24="
)


def upgrade() -> None:
    """Create the CYBERDEFENSE-X system automation user."""

    connection = op.get_bind()

    connection.execute(
        text(
            """
            INSERT INTO users (
                username,
                email,
                password_hash,
                full_name,
                is_active,
                is_superuser
            )
            VALUES (
                :username,
                :email,
                :password_hash,
                :full_name,
                FALSE,
                FALSE
            )
            ON CONFLICT (username) DO NOTHING
            """
        ),
        {
            "username": SYSTEM_USERNAME,
            "email": SYSTEM_EMAIL,
            "password_hash": SYSTEM_PASSWORD_HASH,
            "full_name": "CYBERDEFENSE-X System Automation",
        },
    )


def downgrade() -> None:
    """Remove the CYBERDEFENSE-X system automation user."""

    connection = op.get_bind()

    connection.execute(
        text(
            """
            DELETE FROM users
            WHERE username = :username
              AND email = :email
            """
        ),
        {
            "username": SYSTEM_USERNAME,
            "email": SYSTEM_EMAIL,
        },
    )
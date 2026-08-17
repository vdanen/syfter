"""Add role column to api_keys for RBAC

Revision ID: 007
Revises: 006
Create Date: 2026-08-17

Adds a 'role' column (read/write/admin) to api_keys, backfilling
from the existing is_admin boolean.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("role", sa.String(10), nullable=False, server_default="write"),
    )
    op.execute("UPDATE api_keys SET role = 'admin' WHERE is_admin = true")


def downgrade() -> None:
    op.drop_column("api_keys", "role")

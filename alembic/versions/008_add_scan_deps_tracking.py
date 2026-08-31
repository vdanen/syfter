"""Add deps_status and deps_count columns to scans

Revision ID: 008
Revises: 007
Create Date: 2026-08-31

Tracks background dependency insertion progress per scan.
Without these columns, CycloneDX/SPDX imports with dependency
data hit an unhandled 500 when the code sets scan.deps_status.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("deps_status", sa.String(20), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("deps_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("scans", "deps_count")
    op.drop_column("scans", "deps_status")

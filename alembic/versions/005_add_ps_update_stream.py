"""Add ps_update_stream and ps_module to products

Revision ID: 005
Revises: 004
Create Date: 2026-06-13

Adds OSIDB ps_update_stream and ps_module fields to the products table
for vulnerability correlation (e.g., rhel-9.6.z, rhel-9).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("products", sa.Column("ps_update_stream", sa.String(100), nullable=True))
    op.add_column("products", sa.Column("ps_module", sa.String(100), nullable=True))
    op.create_index("idx_products_ps_update_stream", "products", ["ps_update_stream"])


def downgrade() -> None:
    op.drop_index("idx_products_ps_update_stream", table_name="products")
    op.drop_column("products", "ps_module")
    op.drop_column("products", "ps_update_stream")

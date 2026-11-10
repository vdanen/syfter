"""Add VULCAN analysis tables

Revision ID: 006
Revises: 005
Create Date: 2026-07-07

Adds vulcan_analyses and vulcan_trackers tables for CVE impact
analysis with container layer deduplication (VULCAN pipeline).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vulcan_analyses",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(20), nullable=True),
        sa.Column("component", sa.String(500), nullable=False),
        sa.Column("ps_module", sa.String(100), nullable=True),
        sa.Column("impact", sa.String(20), nullable=True),
        sa.Column("total_products", sa.Integer(), server_default="0"),
        sa.Column("rhel_repos", sa.Integer(), server_default="0"),
        sa.Column("base_images", sa.Integer(), server_default="0"),
        sa.Column("layered_containers", sa.Integer(), server_default="0"),
        sa.Column("app_layer_unique", sa.Integer(), server_default="0"),
        sa.Column("recommended_trackers", sa.Integer(), server_default="0"),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("analyzed_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_by", sa.String(100), nullable=True),
    )
    op.create_index("idx_va_cve", "vulcan_analyses", ["cve_id"])
    op.create_index("idx_va_component", "vulcan_analyses", ["component"])
    op.create_index("idx_va_status", "vulcan_analyses", ["status"])

    op.create_table(
        "vulcan_trackers",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "analysis_id",
            sa.Integer(),
            sa.ForeignKey("vulcan_analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tracker_type", sa.String(20), nullable=False),
        sa.Column("product_name", sa.String(255), nullable=False),
        sa.Column("product_version", sa.String(100), nullable=False),
        sa.Column("covers_count", sa.Integer(), server_default="0"),
        sa.Column("covered_products_json", sa.Text(), nullable=True),
        sa.Column("package_version", sa.String(200), nullable=True),
        sa.Column("package_arch", sa.String(50), nullable=True),
        sa.Column("status", sa.String(20), server_default="open"),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_by", sa.String(100), nullable=True),
    )
    op.create_index("idx_vt_analysis", "vulcan_trackers", ["analysis_id"])
    op.create_index(
        "idx_vt_product", "vulcan_trackers", ["product_name", "product_version"]
    )


def downgrade() -> None:
    op.drop_index("idx_vt_product", table_name="vulcan_trackers")
    op.drop_index("idx_vt_analysis", table_name="vulcan_trackers")
    op.drop_table("vulcan_trackers")
    op.drop_index("idx_va_status", table_name="vulcan_analyses")
    op.drop_index("idx_va_component", table_name="vulcan_analyses")
    op.drop_index("idx_va_cve", table_name="vulcan_analyses")
    op.drop_table("vulcan_analyses")

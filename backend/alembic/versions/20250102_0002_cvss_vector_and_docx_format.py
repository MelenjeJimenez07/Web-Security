"""Add cvss_vector column to findings and docx value to report_format enum.

Revision ID: 20250102_0002
Revises: 20250101_0001
Create Date: 2025-01-02 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20250102_0002"
down_revision: str | Sequence[str] | None = "20250101_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE report_format ADD VALUE IF NOT EXISTS 'docx'")

    op.add_column("findings", sa.Column("cvss_vector", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "cvss_vector")

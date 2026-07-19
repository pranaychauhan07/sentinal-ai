"""create case_notes and case_tags tables

Revision ID: e20964e060ee
Revises: 031e35cdb9e7
Create Date: 2026-07-20 02:00:10.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e20964e060ee'
down_revision: str | None = '031e35cdb9e7'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'case_notes',
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('author_id', sa.String(length=255), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_case_notes_case_id', 'case_notes', ['case_id'], unique=False)

    op.create_table(
        'case_tags',
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('tag', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'tag', name='uq_case_tags_case_id_tag'),
    )
    op.create_index('ix_case_tags_case_id', 'case_tags', ['case_id'], unique=False)
    op.create_index('ix_case_tags_tag', 'case_tags', ['tag'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_case_tags_tag', table_name='case_tags')
    op.drop_index('ix_case_tags_case_id', table_name='case_tags')
    op.drop_table('case_tags')
    op.drop_index('ix_case_notes_case_id', table_name='case_notes')
    op.drop_table('case_notes')

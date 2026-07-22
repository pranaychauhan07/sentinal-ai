"""create conversation_sessions, conversation_messages, conversation_summaries tables

Revision ID: a1b2c3d4e5f6
Revises: e6f0a3c8b9d5
Create Date: 2026-07-22 09:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: str | None = 'e6f0a3c8b9d5'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'conversation_sessions',
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('turn_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_active_at', sa.DateTime(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_conversation_sessions_case_id', 'conversation_sessions', ['case_id'], unique=False
    )

    op.create_table(
        'conversation_messages',
        sa.Column('session_id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('sequence_index', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(length=16), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('citations_json', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('degraded', sa.Boolean(), nullable=False),
        sa.Column('selected_categories_json', sa.Text(), nullable=False),
        sa.Column('prompt_injection_flagged', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['conversation_sessions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_conversation_messages_session_id',
        'conversation_messages',
        ['session_id', 'sequence_index'],
        unique=False,
    )
    op.create_index(
        'ix_conversation_messages_case_id', 'conversation_messages', ['case_id'], unique=False
    )

    op.create_table(
        'conversation_summaries',
        sa.Column('session_id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('summary_text', sa.Text(), nullable=False),
        sa.Column('covers_through_sequence_index', sa.Integer(), nullable=False),
        sa.Column('summarized_message_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['conversation_sessions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_conversation_summaries_session_id',
        'conversation_summaries',
        ['session_id'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index('ix_conversation_summaries_session_id', table_name='conversation_summaries')
    op.drop_table('conversation_summaries')
    op.drop_index('ix_conversation_messages_case_id', table_name='conversation_messages')
    op.drop_index('ix_conversation_messages_session_id', table_name='conversation_messages')
    op.drop_table('conversation_messages')
    op.drop_index('ix_conversation_sessions_case_id', table_name='conversation_sessions')
    op.drop_table('conversation_sessions')

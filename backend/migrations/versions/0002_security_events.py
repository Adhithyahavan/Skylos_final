"""security_events - canonical normalized SecurityEvent table

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-01

Adds the canonical SecurityEvent store. `event_id` is unique (UUID assigned at
normalization) and `raw_event_reference` is unique so a raw record (for
example "logs:42") can never produce two normalized events.

Downgrade drops only this table, which this revision created. Its rows are
derived from raw records (logs) that remain in place.
"""
from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('security_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('event_id', sa.String(length=36), nullable=False),
    sa.Column('event_type', sa.String(length=50), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('ingestion_timestamp', sa.DateTime(), nullable=False),
    sa.Column('source_type', sa.String(length=50), nullable=False),
    sa.Column('source_id', sa.String(length=100), nullable=True),
    sa.Column('asset_id', sa.Integer(), nullable=True),
    sa.Column('device_id', sa.String(length=100), nullable=True),
    sa.Column('actor', sa.String(length=255), nullable=True),
    sa.Column('actor_type', sa.String(length=30), nullable=True),
    sa.Column('source_address', sa.String(length=45), nullable=True),
    sa.Column('destination_address', sa.String(length=45), nullable=True),
    sa.Column('action', sa.String(length=50), nullable=False),
    sa.Column('object_type', sa.String(length=50), nullable=True),
    sa.Column('object_name', sa.String(length=255), nullable=True),
    sa.Column('outcome', sa.String(length=20), nullable=False),
    sa.Column('severity_hint', sa.String(length=20), nullable=True),
    sa.Column('raw_event_reference', sa.String(length=100), nullable=True),
    sa.Column('attributes', sa.JSON(), nullable=True),
    sa.Column('correlation_key', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('event_id'),
    sa.UniqueConstraint('raw_event_reference')
    )
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_security_events_actor'), ['actor'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_asset_id'), ['asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_correlation_key'), ['correlation_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_event_type'), ['event_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_source_address'), ['source_address'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_source_type'), ['source_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_events_timestamp'), ['timestamp'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_security_events_timestamp'))
        batch_op.drop_index(batch_op.f('ix_security_events_source_type'))
        batch_op.drop_index(batch_op.f('ix_security_events_source_address'))
        batch_op.drop_index(batch_op.f('ix_security_events_id'))
        batch_op.drop_index(batch_op.f('ix_security_events_event_type'))
        batch_op.drop_index(batch_op.f('ix_security_events_correlation_key'))
        batch_op.drop_index(batch_op.f('ix_security_events_asset_id'))
        batch_op.drop_index(batch_op.f('ix_security_events_actor'))

    op.drop_table('security_events')

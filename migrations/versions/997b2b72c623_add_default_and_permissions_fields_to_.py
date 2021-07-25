"""Add default and permissions fields to the Role model

Revision ID: 997b2b72c623
Revises: 8dce5521c081
Create Date: 2021-07-21 14:14:05.029999

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '997b2b72c623'
down_revision = '8dce5521c081'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('permissions', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_roles_default'), 'roles', ['default'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_default'), table_name='roles')
    op.drop_column('roles', 'permissions')
    op.drop_column('roles', 'default')
    # ### end Alembic commands ###
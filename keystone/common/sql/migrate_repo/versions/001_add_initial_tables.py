from sqlalchemy import *
from migrate import *

from keystone.common import sql

# these are to make sure all the models we care about are defined
import keystone.identity.backends.sql
import keystone.contrib.ec2.backends.sql


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    sql.ModelBase.metadata.create_all(migrate_engine)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pass

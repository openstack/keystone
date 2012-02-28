# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from sqlalchemy import *
from migrate import *

from keystone.common import sql

# these are to make sure all the models we care about are defined
import keystone.identity.backends.sql
import keystone.token.backends.sql
import keystone.contrib.ec2.backends.sql
import keystone.catalog.backends.sql


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    sql.ModelBase.metadata.create_all(migrate_engine)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pass

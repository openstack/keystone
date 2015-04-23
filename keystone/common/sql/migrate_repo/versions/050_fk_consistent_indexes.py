# Copyright 2014 Mirantis.inc
# All Rights Reserved.
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

import sqlalchemy as sa


def upgrade(migrate_engine):

    if migrate_engine.name == 'mysql':
        meta = sa.MetaData(bind=migrate_engine)
        endpoint = sa.Table('endpoint', meta, autoload=True)

        # NOTE(i159): MySQL requires indexes on referencing columns, and those
        # indexes create automatically. That those indexes will have different
        # names, depending on version of MySQL used. We shoud make this naming
        # consistent, by reverting index name to a consistent condition.
        if any(i for i in endpoint.indexes if
               list(i.columns.keys()) == ['service_id']
               and i.name != 'service_id'):
            # NOTE(i159): by this action will be made re-creation of an index
            # with the new name. This can be considered as renaming under the
            # MySQL rules.
            sa.Index('service_id', endpoint.c.service_id).create()

        user_group_membership = sa.Table('user_group_membership',
                                         meta, autoload=True)

        if any(i for i in user_group_membership.indexes if
               list(i.columns.keys()) == ['group_id']
               and i.name != 'group_id'):
            sa.Index('group_id', user_group_membership.c.group_id).create()

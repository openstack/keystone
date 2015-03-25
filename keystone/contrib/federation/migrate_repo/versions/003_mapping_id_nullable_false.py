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
    meta = sa.MetaData(bind=migrate_engine)
    federation_protocol = sa.Table('federation_protocol', meta, autoload=True)
    # NOTE(i159): The column is changed to non-nullable. To prevent
    # database errors when the column will be altered, all the existing
    # null-records should be filled with not null values.
    stmt = (federation_protocol.update().
            where(federation_protocol.c.mapping_id.is_(None)).
            values(mapping_id=''))
    migrate_engine.execute(stmt)
    federation_protocol.c.mapping_id.alter(nullable=False)

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

from oslo_serialization import jsonutils
import sqlalchemy as sql


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    trust_table = sql.Table('trust', meta, autoload=True)
    trust_list = list(trust_table.select().execute())

    # Loop through all the trusts and move the redelegeated trust id out of
    # extras.
    for trust in trust_list:
        if trust.extra is not None:
            extra_dict = jsonutils.loads(trust.extra)
        else:
            extra_dict = {}

        new_values = {}

        new_values['redelegated_trust_id'] = extra_dict.pop(
            'redelegated_trust_id', None)
        new_values['redelegation_count'] = extra_dict.pop(
            'redelegation_count', None)

        new_values['extra'] = jsonutils.dumps(extra_dict)

        clause = trust_table.c.id == trust.id
        update = trust_table.update().where(clause).values(new_values)
        migrate_engine.execute(update)

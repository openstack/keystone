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

from oslo_config import cfg
from oslo_db.sqlalchemy import utils
import sqlalchemy as sql


CONF = cfg.CONF
_SP_TABLE_NAME = 'service_provider'
_RELAY_STATE_PREFIX = 'relay_state_prefix'


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    idp_table = utils.get_table(migrate_engine, _SP_TABLE_NAME)
    relay_state_prefix_default = CONF.saml.relay_state_prefix
    relay_state_prefix = sql.Column(_RELAY_STATE_PREFIX, sql.String(256),
                                    nullable=False,
                                    server_default=relay_state_prefix_default)
    idp_table.create_column(relay_state_prefix)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    idp_table = utils.get_table(migrate_engine, _SP_TABLE_NAME)
    idp_table.drop_column(_RELAY_STATE_PREFIX)

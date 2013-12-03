# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from sqlalchemy.orm import exc

from keystone.contrib.kds.common import exception
from keystone.contrib.kds.db import connection
from keystone.contrib.kds.db.sqlalchemy import models
from keystone.openstack.common.db.sqlalchemy import session as db_session


def get_backend():
    return SqlalchemyDbImpl()


class SqlalchemyDbImpl(connection.Connection):

    def set_key(self, name, key, signature, group, expiration=None):
        session = db_session.get_session()

        with session.begin():
            q = session.query(models.Host)
            q = q.filter(models.Host.name == name)

            try:
                host = q.one()
            except exc.NoResultFound:
                host = models.Host(name=name,
                                   latest_generation=0,
                                   group=group)
            else:
                if host.group != group:
                    raise exception.GroupStatusChanged(name=name)

            host.latest_generation += 1
            host.keys.append(models.Key(signature=signature,
                                        enc_key=key,
                                        generation=host.latest_generation,
                                        expiration=expiration))

            session.add(host)

        return host.latest_generation

    def get_key(self, name, generation=None, group=None):
        session = db_session.get_session()

        query = session.query(models.Host, models.Key)
        query = query.filter(models.Host.id == models.Key.host_id)
        query = query.filter(models.Host.name == name)

        if group is not None:
            query = query.filter(models.Host.group == group)

        if generation is not None:
            query = query.filter(models.Key.generation == generation)
        else:
            query = query.filter(models.Host.latest_generation ==
                                 models.Key.generation)

        try:
            result = query.one()
        except exc.NoResultFound:
            return None

        return {'name': result.Host.name,
                'group': result.Host.group,
                'key': result.Key.enc_key,
                'signature': result.Key.signature,
                'generation': result.Key.generation,
                'expiration': result.Key.expiration}

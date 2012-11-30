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

import json
import uuid

import sqlalchemy as sql
from sqlalchemy import orm


ENDPOINT_TYPES = ['public', 'internal', 'admin']


def upgrade(migrate_engine):
    """Split each legacy endpoint into seperate records for each interface."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    legacy_table = sql.Table('endpoint_v2', meta, autoload=True)
    new_table = sql.Table('endpoint_v3', meta, autoload=True)

    session = orm.sessionmaker(bind=migrate_engine)()
    for ref in session.query(legacy_table).all():
        # pull urls out of extra
        extra = json.loads(ref.extra)
        urls = dict((i, extra.pop('%surl' % i)) for i in ENDPOINT_TYPES)

        for interface in ENDPOINT_TYPES:
            endpoint = {
                'id': uuid.uuid4().hex,
                'legacy_endpoint_id': ref.id,
                'interface': interface,
                'region': ref.region,
                'service_id': ref.service_id,
                'url': urls[interface],
                'extra': json.dumps(extra),
            }
            session.execute(
                'INSERT INTO `%s` (%s) VALUES (%s)' % (
                new_table.name,
                ', '.join('%s' % k for k in endpoint.keys()),
                ', '.join("'%s'" % v for v in endpoint.values())))
    session.commit()


def downgrade(migrate_engine):
    """Re-create the v2 endpoints table based on v3 endpoints."""
    meta = sql.MetaData()
    meta.bind = migrate_engine

    legacy_table = sql.Table('endpoint_v2', meta, autoload=True)
    new_table = sql.Table('endpoint_v3', meta, autoload=True)

    session = orm.sessionmaker(bind=migrate_engine)()
    for ref in session.query(new_table).all():
        extra = json.loads(ref.extra)
        extra['%surl' % ref.interface] = ref.url
        endpoint = {
            'id': ref.legacy_endpoint_id,
            'region': ref.region,
            'service_id': ref.service_id,
            'extra': json.dumps(extra),
        }

        try:
            session.execute(
                'INSERT INTO `%s` (%s) VALUES (%s)' % (
                legacy_table.name,
                ', '.join('%s' % k for k in endpoint.keys()),
                ', '.join("'%s'" % v for v in endpoint.values())))
        except sql.exc.IntegrityError:
            q = session.query(legacy_table)
            q = q.filter_by(id=ref.legacy_endpoint_id)
            legacy_ref = q.one()
            extra = json.loads(legacy_ref.extra)
            extra['%surl' % ref.interface] = ref.url

            session.execute(
                'UPDATE `%s` SET extra=\'%s\' WHERE id="%s"' % (
                legacy_table.name,
                json.dumps(extra),
                legacy_ref.id))
    session.commit()

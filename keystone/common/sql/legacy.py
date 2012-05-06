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

import re

import sqlalchemy

from keystone.identity.backends import sql as identity_sql


def export_db(db):
    table_names = db.table_names()

    migration_data = {}
    for table_name in table_names:
        query = db.execute("select * from %s" % table_name)
        table_data = []
        for row in query.fetchall():
            entry = {}
            for k in row.keys():
                entry[k] = row[k]
            table_data.append(entry)

        migration_data[table_name] = table_data

    return migration_data


def _translate_replacements(s):
    if '%' not in str(s):
        return s
    return re.sub(r'%([\w_]+)%', r'$(\1)s', s)


class LegacyMigration(object):
    def __init__(self, db_string):
        self.db = sqlalchemy.create_engine(db_string)
        self.identity_driver = identity_sql.Identity()
        self.identity_driver.db_sync()
        self._data = {}
        self._user_map = {}
        self._tenant_map = {}
        self._role_map = {}

    def migrate_all(self):
        self._export_legacy_db()
        self._migrate_tenants()
        self._migrate_users()
        self._migrate_roles()
        self._migrate_user_roles()
        self._migrate_tokens()

    def dump_catalog(self):
        """Generate the contents of a catalog templates file."""
        self._export_legacy_db()

        services_by_id = dict((x['id'], x) for x in self._data['services'])
        template = 'catalog.%(region)s.%(service_type)s.%(key)s = %(value)s'

        o = []
        for row in self._data['endpoint_templates']:
            service = services_by_id[row['service_id']]
            d = {'service_type': service['type'],
                 'region': row['region']}

            for x in ['internal_url', 'public_url', 'admin_url', 'enabled']:
                d['key'] = x.replace('_url', 'URL')
                d['value'] = _translate_replacements(row[x])
                o.append(template % d)

            d['key'] = 'name'
            d['value'] = service['desc']
            o.append(template % d)

        return o

    def _export_legacy_db(self):
        self._data = export_db(self.db)

    def _migrate_tenants(self):
        for x in self._data['tenants']:
            # map
            new_dict = {'description': x.get('desc', ''),
                        'id': x.get('uid', x.get('id')),
                        'enabled': x.get('enabled', True)}
            new_dict['name'] = x.get('name', new_dict.get('id'))
            # track internal ids
            self._tenant_map[x.get('id')] = new_dict['id']
            # create
            #print 'create_tenant(%s, %s)' % (new_dict['id'], new_dict)
            self.identity_driver.create_tenant(new_dict['id'], new_dict)

    def _migrate_users(self):
        for x in self._data['users']:
            # map
            new_dict = {'email': x.get('email', ''),
                        'password': x.get('password', None),
                        'id': x.get('uid', x.get('id')),
                        'enabled': x.get('enabled', True)}
            if x.get('tenant_id'):
                new_dict['tenant_id'] = self._tenant_map.get(x['tenant_id'])
            new_dict['name'] = x.get('name', new_dict.get('id'))
            # track internal ids
            self._user_map[x.get('id')] = new_dict['id']
            # create
            #print 'create_user(%s, %s)' % (new_dict['id'], new_dict)
            self.identity_driver.create_user(new_dict['id'], new_dict)
            if new_dict.get('tenant_id'):
                self.identity_driver.add_user_to_tenant(new_dict['tenant_id'],
                                                        new_dict['id'])

    def _migrate_roles(self):
        for x in self._data['roles']:
            # map
            new_dict = {'id': x['id'],
                        'name': x.get('name', x['id'])}
            # track internal ids
            self._role_map[x.get('id')] = new_dict['id']
            # create
            self.identity_driver.create_role(new_dict['id'], new_dict)

    def _migrate_user_roles(self):
        for x in self._data['user_roles']:
            # map
            if (not x.get('user_id')
                or not x.get('tenant_id')
                or not x.get('role_id')):
                continue
            user_id = self._user_map[x['user_id']]
            tenant_id = self._tenant_map[x['tenant_id']]
            role_id = self._role_map[x['role_id']]

            try:
                self.identity_driver.add_user_to_tenant(tenant_id, user_id)
            except Exception:
                pass

            self.identity_driver.add_role_to_user_and_tenant(
                    user_id, tenant_id, role_id)

    def _migrate_tokens(self):
        pass

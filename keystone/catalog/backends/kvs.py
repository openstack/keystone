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


from keystone import catalog
from keystone import exception
from keystone.common import kvs


class Catalog(kvs.Base, catalog.Driver):
    # Public interface
    def get_catalog(self, user_id, tenant_id, metadata=None):
        return self.db.get('catalog-%s-%s' % (tenant_id, user_id))

    def get_service(self, service_id):
        res = self.db.get('service-%s' % service_id)
        if not res:
            raise exception.ServiceNotFound(service_id=service_id)
        return res

    def list_services(self):
        return self.db.get('service_list', [])

    def create_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        service_list = set(self.db.get('service_list', []))
        service_list.add(service_id)
        self.db.set('service_list', list(service_list))
        return service

    def update_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        return service

    def delete_service(self, service_id):
        if not self.db.get('service-%s' % service_id):
            raise exception.ServiceNotFound(service_id=service_id)

        self.db.delete('service-%s' % service_id)
        service_list = set(self.db.get('service_list', []))
        service_list.remove(service_id)
        self.db.set('service_list', list(service_list))
        return None

    # Private interface
    def _create_catalog(self, user_id, tenant_id, data):
        self.db.set('catalog-%s-%s' % (tenant_id, user_id), data)
        return data

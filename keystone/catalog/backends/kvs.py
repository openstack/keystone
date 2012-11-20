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
from keystone.common import kvs


class Catalog(kvs.Base, catalog.Driver):
    # Public interface
    def get_catalog(self, user_id, tenant_id, metadata=None):
        return self.db.get('catalog-%s-%s' % (tenant_id, user_id))

    # service crud

    def create_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        service_list = set(self.db.get('service_list', []))
        service_list.add(service_id)
        self.db.set('service_list', list(service_list))
        return service

    def list_services(self):
        return [self.get_service(x) for x in self.db.get('service_list', [])]

    def get_service(self, service_id):
        return self.db.get('service-%s' % service_id)

    def update_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        return service

    def delete_service(self, service_id):
        # delete referencing endpoints
        for endpoint_id in self.db.get('endpoint_list', []):
            if self.get_endpoint(endpoint_id)['service_id'] == service_id:
                self.delete_endpoint(endpoint_id)

        self.db.delete('service-%s' % service_id)
        service_list = set(self.db.get('service_list', []))
        service_list.remove(service_id)
        self.db.set('service_list', list(service_list))

    # endpoint crud

    def create_endpoint(self, endpoint_id, endpoint):
        self.get_service(endpoint['service_id'])
        self.db.set('endpoint-%s' % endpoint_id, endpoint)
        endpoint_list = set(self.db.get('endpoint_list', []))
        endpoint_list.add(endpoint_id)
        self.db.set('endpoint_list', list(endpoint_list))
        return endpoint

    def list_endpoints(self):
        return [self.get_endpoint(x) for x in self.db.get('endpoint_list', [])]

    def get_endpoint(self, endpoint_id):
        return self.db.get('endpoint-%s' % endpoint_id)

    def update_endpoint(self, endpoint_id, endpoint):
        self.db.set('endpoint-%s' % endpoint_id, endpoint)
        return endpoint

    def delete_endpoint(self, endpoint_id):
        self.db.delete('endpoint-%s' % endpoint_id)
        endpoint_list = set(self.db.get('endpoint_list', []))
        endpoint_list.remove(endpoint_id)
        self.db.set('endpoint_list', list(endpoint_list))

    # Private interface
    def _create_catalog(self, user_id, tenant_id, data):
        self.db.set('catalog-%s-%s' % (tenant_id, user_id), data)
        return data

# Copyright 2012 OpenStack Foundation
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
from keystone.common import driver_hints
from keystone.common import kvs


class Catalog(kvs.Base, catalog.CatalogDriverV8):
    # Public interface
    def get_catalog(self, user_id, tenant_id):
        return self.db.get('catalog-%s-%s' % (tenant_id, user_id))

    # region crud

    def _delete_child_regions(self, region_id, root_region_id):
        """Delete all child regions.

        Recursively delete any region that has the supplied region
        as its parent.
        """
        children = [r for r in self.list_regions(driver_hints.Hints())
                    if r['parent_region_id'] == region_id]
        for child in children:
            if child['id'] == root_region_id:
                # Hit a circular region hierarchy
                return
            self._delete_child_regions(child['id'], root_region_id)
            self._delete_region(child['id'])

    def _check_parent_region(self, region_ref):
        """Raise a NotFound if the parent region does not exist.

        If the region_ref has a specified parent_region_id, check that
        the parent exists, otherwise, raise a NotFound.
        """
        parent_region_id = region_ref.get('parent_region_id')
        if parent_region_id is not None:
            # This will raise NotFound if the parent doesn't exist,
            # which is the behavior we want.
            self.get_region(parent_region_id)

    def create_region(self, region):
        region_id = region['id']
        region.setdefault('parent_region_id')
        self._check_parent_region(region)
        self.db.set('region-%s' % region_id, region)
        region_list = set(self.db.get('region_list', []))
        region_list.add(region_id)
        self.db.set('region_list', list(region_list))
        return region

    def list_regions(self, hints):
        return [self.get_region(x) for x in self.db.get('region_list', [])]

    def get_region(self, region_id):
        return self.db.get('region-%s' % region_id)

    def update_region(self, region_id, region):
        self._check_parent_region(region)
        old_region = self.get_region(region_id)
        old_region.update(region)
        self._ensure_no_circle_in_hierarchical_regions(old_region)
        self.db.set('region-%s' % region_id, old_region)
        return old_region

    def _delete_region(self, region_id):
        self.db.delete('region-%s' % region_id)
        region_list = set(self.db.get('region_list', []))
        region_list.remove(region_id)
        self.db.set('region_list', list(region_list))

    def delete_region(self, region_id):
        self._delete_child_regions(region_id, region_id)
        self._delete_region(region_id)

    # service crud

    def create_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        service_list = set(self.db.get('service_list', []))
        service_list.add(service_id)
        self.db.set('service_list', list(service_list))
        return service

    def list_services(self, hints):
        return [self.get_service(x) for x in self.db.get('service_list', [])]

    def get_service(self, service_id):
        return self.db.get('service-%s' % service_id)

    def update_service(self, service_id, service):
        old_service = self.get_service(service_id)
        old_service.update(service)
        self.db.set('service-%s' % service_id, old_service)
        return old_service

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
        self.db.set('endpoint-%s' % endpoint_id, endpoint)
        endpoint_list = set(self.db.get('endpoint_list', []))
        endpoint_list.add(endpoint_id)
        self.db.set('endpoint_list', list(endpoint_list))
        return endpoint

    def list_endpoints(self, hints):
        return [self.get_endpoint(x) for x in self.db.get('endpoint_list', [])]

    def get_endpoint(self, endpoint_id):
        return self.db.get('endpoint-%s' % endpoint_id)

    def update_endpoint(self, endpoint_id, endpoint):
        if endpoint.get('region_id') is not None:
            self.get_region(endpoint['region_id'])

        old_endpoint = self.get_endpoint(endpoint_id)
        old_endpoint.update(endpoint)
        self.db.set('endpoint-%s' % endpoint_id, old_endpoint)
        return old_endpoint

    def delete_endpoint(self, endpoint_id):
        self.db.delete('endpoint-%s' % endpoint_id)
        endpoint_list = set(self.db.get('endpoint_list', []))
        endpoint_list.remove(endpoint_id)
        self.db.set('endpoint_list', list(endpoint_list))

    # Private interface
    def _create_catalog(self, user_id, tenant_id, data):
        self.db.set('catalog-%s-%s' % (tenant_id, user_id), data)
        return data

# Copyright 2018 Huawei
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

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

MEMOIZE = cache.get_memoization_decorator(group='unified_limit')


class Manager(manager.Manager):

    driver_namespace = 'keystone.unified_limit'
    _provides_api = 'unified_limit_api'

    def __init__(self):
        unified_limit_driver = CONF.unified_limit.driver
        super(Manager, self).__init__(unified_limit_driver)

    def _assert_resource_exist(self, unified_limit, target):
        try:
            service_id = unified_limit.get('service_id')
            if service_id is not None:
                PROVIDERS.catalog_api.get_service(service_id)
            region_id = unified_limit.get('region_id')
            if region_id is not None:
                PROVIDERS.catalog_api.get_region(region_id)
            project_id = unified_limit.get('project_id')
            if project_id is not None:
                PROVIDERS.resource_api.get_project(project_id)
        except exception.ServiceNotFound:
            raise exception.ValidationError(attribute='service_id',
                                            target=target)
        except exception.RegionNotFound:
            raise exception.ValidationError(attribute='region_id',
                                            target=target)
        except exception.ProjectNotFound:
            raise exception.ValidationError(attribute='project_id',
                                            target=target)

    def create_registered_limits(self, registered_limits):
        for registered_limit in registered_limits:
            self._assert_resource_exist(registered_limit, 'registered_limit')
        self.driver.create_registered_limits(registered_limits)
        return self.list_registered_limits()

    def update_registered_limits(self, registered_limits):
        for registered_limit in registered_limits:
            self._assert_resource_exist(registered_limit, 'registered_limit')
        self.driver.update_registered_limits(registered_limits)
        for registered_limit in registered_limits:
            self.get_registered_limit.invalidate(self, registered_limit['id'])
        return self.list_registered_limits()

    @manager.response_truncated
    def list_registered_limits(self, hints=None):
        return self.driver.list_registered_limits(
            hints or driver_hints.Hints())

    @MEMOIZE
    def get_registered_limit(self, registered_limit_id):
        return self.driver.get_registered_limit(registered_limit_id)

    def delete_registered_limit(self, registered_limit_id):
        self.driver.delete_registered_limit(registered_limit_id)
        self.get_registered_limit.invalidate(self, registered_limit_id)

    def create_limits(self, limits):
        for limit in limits:
            self._assert_resource_exist(limit, 'limit')
        self.driver.create_limits(limits)
        return self.list_limits()

    def update_limits(self, limits):
        for limit in limits:
            self._assert_resource_exist(limit, 'limit')
        self.driver.update_limits(limits)
        for limit in limits:
            self.get_limit.invalidate(self, limit['id'])
        return self.list_limits()

    @manager.response_truncated
    def list_limits(self, hints=None):
        return self.driver.list_limits(hints or driver_hints.Hints())

    @MEMOIZE
    def get_limit(self, limit_id):
        return self.driver.get_limit(limit_id)

    def delete_limit(self, limit_id):
        self.driver.delete_limit(limit_id)
        self.get_limit.invalidate(self, limit_id)

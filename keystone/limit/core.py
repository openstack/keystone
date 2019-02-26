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
import copy

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.limit.models import base

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

MEMOIZE = cache.get_memoization_decorator(group='unified_limit')


class Manager(manager.Manager):

    driver_namespace = 'keystone.unified_limit'
    _provides_api = 'unified_limit_api'

    def __init__(self):
        unified_limit_driver = CONF.unified_limit.driver
        super(Manager, self).__init__(unified_limit_driver)

        self.enforcement_model = base.load_driver(
            CONF.unified_limit.enforcement_model)

    def check_project_depth(self):
        """Check if project depth satisfies current enforcement model."""
        PROVIDERS.resource_api.check_project_depth(
            self.enforcement_model.MAX_PROJECT_TREE_DEPTH)

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
                project = PROVIDERS.resource_api.get_project(project_id)
                if project['is_domain']:
                    # Treat the input limit as domain level limit.
                    unified_limit['domain_id'] = unified_limit.pop(
                        'project_id')
            domain_id = unified_limit.get('domain_id')
            if domain_id is not None:
                PROVIDERS.resource_api.get_domain(domain_id)

        except exception.ServiceNotFound:
            raise exception.ValidationError(attribute='service_id',
                                            target=target)
        except exception.RegionNotFound:
            raise exception.ValidationError(attribute='region_id',
                                            target=target)
        except exception.ProjectNotFound:
            raise exception.ValidationError(attribute='project_id',
                                            target=target)
        except exception.DomainNotFound:
            raise exception.ValidationError(attribute='domain_id',
                                            target=target)

    def get_model(self):
        """Return information of the configured enforcement model."""
        return {
            'name': self.enforcement_model.NAME,
            'description': self.enforcement_model.DESCRIPTION
        }

    def create_registered_limits(self, registered_limits):
        for registered_limit in registered_limits:
            self._assert_resource_exist(registered_limit, 'registered_limit')
        return self.driver.create_registered_limits(registered_limits)

    def update_registered_limit(self, registered_limit_id, registered_limit):
        self._assert_resource_exist(registered_limit, 'registered_limit')
        updated_registered_limit = self.driver.update_registered_limit(
            registered_limit_id, registered_limit)
        self.get_registered_limit.invalidate(self,
                                             updated_registered_limit['id'])
        return updated_registered_limit

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
        self.enforcement_model.check_limit(copy.deepcopy(limits))
        return self.driver.create_limits(limits)

    def update_limit(self, limit_id, limit):
        self._assert_resource_exist(limit, 'limit')
        limit_ref = self.get_limit(limit_id)
        limit_ref.update(limit)
        self.enforcement_model.check_limit(copy.deepcopy([limit_ref]))
        updated_limit = self.driver.update_limit(limit_id, limit)
        self.get_limit.invalidate(self, updated_limit['id'])
        return updated_limit

    @manager.response_truncated
    def list_limits(self, hints=None):
        return self.driver.list_limits(hints or driver_hints.Hints())

    @MEMOIZE
    def get_limit(self, limit_id):
        return self.driver.get_limit(limit_id)

    def delete_limit(self, limit_id):
        self.driver.delete_limit(limit_id)
        self.get_limit.invalidate(self, limit_id)

    def delete_limits_for_project(self, project_id):
        limit_ids = self.driver.delete_limits_for_project(project_id)
        for limit_id in limit_ids:
            self.get_limit.invalidate(self, limit_id)

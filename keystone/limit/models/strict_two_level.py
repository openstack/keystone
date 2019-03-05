# Copyright 2018 Huawei
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

from oslo_log import log

from keystone.common import driver_hints
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _
from keystone.limit.models import base

LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class StrictTwoLevelModel(base.ModelBase):
    NAME = 'strict_two_level'
    DESCRIPTION = (
        'This model requires project hierarchy never exceeds a depth of two'
    )
    MAX_PROJECT_TREE_DEPTH = 2

    def _get_specified_limit_value(self, resource_name, service_id,
                                   region_id, project_id=None, domain_id=None):
        """Get the specified limit value.

        Try to give the resource limit first. If the specified limit is a
        domain limit and the resource limit value is None, get the related
        registered limit value instead.

        """
        hints = driver_hints.Hints()
        if project_id:
            hints.add_filter('project_id', project_id)
        else:
            hints.add_filter('domain_id', domain_id)
        hints.add_filter('service_id', service_id)
        hints.add_filter('resource_name', resource_name)
        hints.add_filter('region_id', region_id)
        limits = PROVIDERS.unified_limit_api.list_limits(hints)
        limit_value = limits[0]['resource_limit'] if limits else None
        if not limits and domain_id:
            hints = driver_hints.Hints()
            hints.add_filter('service_id', service_id)
            hints.add_filter('resource_name', resource_name)
            hints.add_filter('region_id', region_id)
            limits = PROVIDERS.unified_limit_api.list_registered_limits(hints)
            limit_value = limits[0]['default_limit'] if limits else None
        return limit_value

    def _check_limit(self, resource_name, service_id, region_id,
                     resource_limit, domain_id=None, parent_id=None):
        """Check the specified limit value satisfies the related project tree.

        1. Ensure the limit is smaller than its parent.
        2. Ensure the limit is bigger than its children.

        """
        if parent_id:
            # This is a project limit, need make sure its limit is not bigger
            # than its parent.
            parent_limit_value = self._get_specified_limit_value(
                resource_name, service_id, region_id, domain_id=parent_id)
            if parent_limit_value and resource_limit > parent_limit_value:
                raise exception.InvalidLimit(
                    reason="Limit is bigger than parent.")
        else:
            # This is a domain limit, need make sure its limit is not smaller
            # than its children.
            sub_projects = PROVIDERS.resource_api.list_projects_in_subtree(
                domain_id)
            for sub_project in sub_projects:
                sub_limit_value = self._get_specified_limit_value(
                    resource_name, service_id, region_id,
                    project_id=sub_project['id'])
                if sub_limit_value and resource_limit < sub_limit_value:
                    raise exception.InvalidLimit(
                        reason="Limit is smaller than child.")

    def check_limit(self, limits):
        """Check the input limits satisfy the related project tree or not.

        1. Ensure the input is legal.
        2. Ensure the input will not break the exist limit tree.

        """
        for limit in limits:
            project_id = limit.get('project_id')
            domain_id = limit.get('domain_id')
            resource_name = limit['resource_name']
            resource_limit = limit['resource_limit']
            service_id = limit['service_id']
            region_id = limit.get('region_id')
            try:
                # Since domain is considered as the first level, if the input
                # limit is project level, its parent must be a domain.
                if project_id:
                    parent_id = PROVIDERS.resource_api.get_project(project_id)[
                        'parent_id']
                    parent_limit = list(filter(
                        lambda x: (x.get('domain_id') == parent_id and
                                   x['service_id'] == service_id and
                                   x.get('region_id') == region_id and
                                   x['resource_name'] == resource_name),
                        limits))
                    if parent_limit:
                        if resource_limit > parent_limit[0]['resource_limit']:
                            error = _("The value of the limit which project is"
                                      " %(project_id)s should not bigger than "
                                      "its parent domain %(domain_id)s.") % {
                                "project_id": project_id,
                                "domain_id": parent_limit[0]['domain_id']}
                            raise exception.InvalidLimit(reason=error)
                        # The limit's parent is in request body, no need to
                        # check the backend limit any more.
                        continue
                else:
                    parent_id = None

                self._check_limit(resource_name, service_id, region_id,
                                  resource_limit, domain_id=domain_id,
                                  parent_id=parent_id)
            except exception.InvalidLimit:
                error = ("The resource limit (%(level)s: %(id)s, "
                         "resource_name: %(resource_name)s, "
                         "resource_limit: %(resource_limit)s, "
                         "service_id: %(service_id)s, "
                         "region_id: %(region_id)s) doesn't satisfy "
                         "current hierarchy model.") % {
                    'level': 'project_id' if project_id else 'domain_id',
                    'id': project_id or domain_id,
                    'resource_name': resource_name,
                    'resource_limit': resource_limit,
                    'service_id': service_id,
                    'region_id': region_id
                }
                tr_error = _("The resource limit (%(level)s: %(id)s, "
                             "resource_name: %(resource_name)s, "
                             "resource_limit: %(resource_limit)s, "
                             "service_id: %(service_id)s, "
                             "region_id: %(region_id)s) doesn't satisfy "
                             "current hierarchy model.") % {
                    'level': 'project_id' if project_id else 'domain_id',
                    'id': project_id or domain_id,
                    'resource_name': resource_name,
                    'resource_limit': resource_limit,
                    'service_id': service_id,
                    'region_id': region_id
                }
                LOG.error(error)
                raise exception.InvalidLimit(reason=tr_error)

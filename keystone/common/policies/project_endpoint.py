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

from oslo_policy import policy

from keystone.common.policies import base

project_endpoint_policies = [

    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_projects_for_endpoint',
        check_str=base.RULE_ADMIN_REQUIRED,
        # NOTE(lbragstad): While projects can be considered project-level APIs
        # with hierarchical multi-tenancy, endpoints are a system-level
        # resource. Managing associations between projects and endpoints should
        # default to system-level.
        scope_types=['system'],
        description='List projects allowed to access an endpoint.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoints/{endpoint_id}/'
                              'projects'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'add_endpoint_to_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Allow project to access an endpoint.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_endpoint_in_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Check if a project is allowed to access an endpoint.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_endpoints_for_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List the endpoints a project is allowed to access.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'remove_endpoint_from_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description=('Remove access to an endpoint from a project that has '
                     'previously been given explicit access.'),
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'DELETE'}])
]


def list_rules():
    return project_endpoint_policies

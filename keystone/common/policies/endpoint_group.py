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

group_endpoint_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_endpoint_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create endpoint group.',
        operations=[{'path': '/v3/OS-EP-FILTER/endpoint_groups',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_endpoint_groups',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List endpoint groups.',
        operations=[{'path': '/v3/OS-EP-FILTER/endpoint_groups',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_endpoint_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Get endpoint group.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}'),
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_endpoint_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update endpoint group.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}'),
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_endpoint_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete endpoint group.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}'),
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_projects_associated_with_endpoint_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description=('List all projects associated with a specific endpoint '
                     'group.'),
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}/projects'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_endpoints_associated_with_endpoint_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List all endpoints associated with an endpoint group.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}/endpoints'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_endpoint_group_in_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description=('Check if an endpoint group is associated with a '
                     'project.'),
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}/projects/{project_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}/projects/{project_id}'),
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_endpoint_groups_for_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List endpoint groups associated with a specific project.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoint_groups'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'add_endpoint_group_to_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Allow a project to access an endpoint group.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}/projects/{project_id}'),
                     'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'remove_endpoint_group_from_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Remove endpoint group from project.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoint_groups/'
                              '{endpoint_group_id}/projects/{project_id}'),
                     'method': 'DELETE'}])
]


def list_rules():
    return group_endpoint_policies

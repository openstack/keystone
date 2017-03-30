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

project_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_project',
        check_str=base.RULE_ADMIN_OR_TARGET_PROJECT,
        description='Show project details.',
        operations=[{'path': '/v3/projects/{project_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_projects',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='List projects.',
        operations=[{'path': '/v3/projects',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_user_projects',
        check_str=base.RULE_ADMIN_OR_OWNER,
        description='List projects for user.',
        operations=[{'path': '/v3/users/{user_id}/projects',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Create project.',
        operations=[{'path': '/v3/projects',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Update project.',
        operations=[{'path': '/v3/projects/{project_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_project',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Delete project.',
        operations=[{'path': '/v3/projects/{project_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return project_policies

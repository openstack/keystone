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

role_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Show role details.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles/{role_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_roles',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='List roles.',
        operations=[{'path': '/v3/roles',
                     'method': 'GET'},
                    {'path': '/v3/roles',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Create role.',
        operations=[{'path': '/v3/roles',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Update role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Delete role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Show domain role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles/{role_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_domain_roles',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='List domain roles.',
        operations=[{'path': '/v3/roles?domain_id={domain_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles?domain_id={domain_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Create domain role.',
        operations=[{'path': '/v3/roles',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Update domain role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Delete domain role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return role_policies

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
        # FIXME(lbragstad): Roles should be considered a system-level resource.
        # The current RBAC design of OpenStack requires configuration
        # modification depending on the roles created in keystone. Once that is
        # no longer true we should consider adding `project` to the list of
        # scope_types.
        scope_types=['system'],
        description='Show role details.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles/{role_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_roles',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List roles.',
        operations=[{'path': '/v3/roles',
                     'method': 'GET'},
                    {'path': '/v3/roles',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create role.',
        operations=[{'path': '/v3/roles',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): Once OpenStack supports a way to make role changes
        # without having to modify policy files, scope_types for
        # domain-specific roles should include `project`. This will expose
        # these APIs to domain/project administrators, allowing them to create,
        # modify, and delete roles for their own projects and domains.
        scope_types=['system'],
        description='Show domain role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles/{role_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_domain_roles',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='List domain roles.',
        scope_types=['system'],
        operations=[{'path': '/v3/roles?domain_id={domain_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles?domain_id={domain_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Create domain role.',
        scope_types=['system'],
        operations=[{'path': '/v3/roles',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Update domain role.',
        scope_types=['system'],
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Delete domain role.',
        scope_types=['system'],
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return role_policies

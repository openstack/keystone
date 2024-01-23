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

from oslo_log import versionutils
from oslo_policy import policy

from keystone.common.policies import base

DEPRECATED_REASON = (
    "The role API is now aware of system scope and default roles."
)

deprecated_get_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_roles',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_get_domain_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_domain_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_list_domain_roles = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_domain_roles',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_update_domain_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_domain_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_create_domain_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_domain_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_delete_domain_role = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_domain_role',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


role_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_role',
        check_str=base.RULE_ADMIN_OR_SYSTEM_READER,
        scope_types=['system', 'project'],
        description='Show role details.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles/{role_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_roles',
        check_str=base.RULE_ADMIN_OR_SYSTEM_READER,
        scope_types=['system', 'project'],
        description='List roles.',
        operations=[{'path': '/v3/roles',
                     'method': 'GET'},
                    {'path': '/v3/roles',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system', 'project'],
        description='Create role.',
        operations=[{'path': '/v3/roles',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system', 'project'],
        description='Update role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system', 'project'],
        description='Delete role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_domain_role',
        check_str=base.RULE_ADMIN_OR_SYSTEM_READER,
        scope_types=['system', 'project'],
        description='Show domain role.',
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles/{role_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_domain_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_domain_roles',
        check_str=base.RULE_ADMIN_OR_SYSTEM_READER,
        description='List domain roles.',
        scope_types=['system', 'project'],
        operations=[{'path': '/v3/roles?domain_id={domain_id}',
                     'method': 'GET'},
                    {'path': '/v3/roles?domain_id={domain_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_domain_roles),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Create domain role.',
        scope_types=['system', 'project'],
        operations=[{'path': '/v3/roles',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_domain_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Update domain role.',
        scope_types=['system', 'project'],
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_domain_role),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_domain_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Delete domain role.',
        scope_types=['system', 'project'],
        operations=[{'path': '/v3/roles/{role_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_domain_role)
]


def list_rules():
    return role_policies

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

SYSTEM_READER_OR_DOMAIN_READER_FOR_TARGET_USER_OR_OWNER = (
    '(role:reader and system_scope:all) or '
    '(role:reader and domain_id:%(target.user.domain_id)s) or '
    'user_id:%(user_id)s'
)

SYSTEM_READER_OR_DOMAIN_READER_FOR_TARGET_GROUP_USER = (
    '(role:reader and system_scope:all) or '
    '(role:reader and '
    'domain_id:%(target.group.domain_id)s and '
    'domain_id:%(target.user.domain_id)s)'
)

SYSTEM_ADMIN_OR_DOMAIN_ADMIN_FOR_TARGET_GROUP_USER = (
    '(role:admin and system_scope:all) or '
    '(role:admin and '
    'domain_id:%(target.group.domain_id)s and '
    'domain_id:%(target.user.domain_id)s)'
)

SYSTEM_READER_OR_DOMAIN_READER = (
    '(role:reader and system_scope:all) or '
    '(role:reader and domain_id:%(target.group.domain_id)s)'
)

SYSTEM_ADMIN_OR_DOMAIN_ADMIN = (
    '(role:admin and system_scope:all) or '
    '(role:admin and domain_id:%(target.group.domain_id)s)'
)

DEPRECATED_REASON = (
    "The group API is now aware of system scope and default roles."
)

deprecated_get_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_groups = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_groups',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_groups_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_groups_for_user',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_users_in_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_users_in_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_check_user_in_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_user_in_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_remove_user_from_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'remove_user_from_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_add_user_to_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'add_user_to_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)

group_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_group',
        check_str=SYSTEM_READER_OR_DOMAIN_READER,
        scope_types=['system', 'domain'],
        description='Show group details.',
        operations=[{'path': '/v3/groups/{group_id}',
                     'method': 'GET'},
                    {'path': '/v3/groups/{group_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_groups',
        check_str=SYSTEM_READER_OR_DOMAIN_READER,
        scope_types=['system', 'domain'],
        description='List groups.',
        operations=[{'path': '/v3/groups',
                     'method': 'GET'},
                    {'path': '/v3/groups',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_groups),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_groups_for_user',
        check_str=SYSTEM_READER_OR_DOMAIN_READER_FOR_TARGET_USER_OR_OWNER,
        scope_types=['system', 'domain', 'project'],
        description='List groups to which a user belongs.',
        operations=[{'path': '/v3/users/{user_id}/groups',
                     'method': 'GET'},
                    {'path': '/v3/users/{user_id}/groups',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_groups_for_user),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_group',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description='Create group.',
        operations=[{'path': '/v3/groups',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_group',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description='Update group.',
        operations=[{'path': '/v3/groups/{group_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_group',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description='Delete group.',
        operations=[{'path': '/v3/groups/{group_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_users_in_group',
        check_str=SYSTEM_READER_OR_DOMAIN_READER,
        scope_types=['system', 'domain'],
        description='List members of a specific group.',
        operations=[{'path': '/v3/groups/{group_id}/users',
                     'method': 'GET'},
                    {'path': '/v3/groups/{group_id}/users',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_users_in_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'remove_user_from_group',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN_FOR_TARGET_GROUP_USER,
        scope_types=['system', 'domain'],
        description='Remove user from group.',
        operations=[{'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_remove_user_from_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_user_in_group',
        check_str=SYSTEM_READER_OR_DOMAIN_READER_FOR_TARGET_GROUP_USER,
        scope_types=['system', 'domain'],
        description='Check whether a user is a member of a group.',
        operations=[{'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'HEAD'},
                    {'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'GET'}],
        deprecated_rule=deprecated_check_user_in_group),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'add_user_to_group',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN_FOR_TARGET_GROUP_USER,
        scope_types=['system', 'domain'],
        description='Add user to group.',
        operations=[{'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'PUT'}],
        deprecated_rule=deprecated_add_user_to_group)
]


def list_rules():
    return group_policies

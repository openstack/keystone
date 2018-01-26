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

group_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): Groups have traditionally been a resource managed
        # by system or cloud administrators. If, or when, keystone supports the
        # ability for groups to be created or managed by project
        # administrators, scope_types should also include 'project'. Until
        # then, let's make sure these APIs are only accessible to system
        # administrators.
        scope_types=['system'],
        description='Show group details.',
        operations=[{'path': '/v3/groups/{group_id}',
                     'method': 'GET'},
                    {'path': '/v3/groups/{group_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_groups',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List groups.',
        operations=[{'path': '/v3/groups',
                     'method': 'GET'},
                    {'path': '/v3/groups',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_groups_for_user',
        check_str=base.RULE_ADMIN_OR_OWNER,
        scope_types=['system'],
        description='List groups to which a user belongs.',
        operations=[{'path': '/v3/users/{user_id}/groups',
                     'method': 'GET'},
                    {'path': '/v3/users/{user_id}/groups',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create group.',
        operations=[{'path': '/v3/groups',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update group.',
        operations=[{'path': '/v3/groups/{group_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete group.',
        operations=[{'path': '/v3/groups/{group_id}',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_users_in_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List members of a specific group.',
        operations=[{'path': '/v3/groups/{group_id}/users',
                     'method': 'GET'},
                    {'path': '/v3/groups/{group_id}/users',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'remove_user_from_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Remove user from group.',
        operations=[{'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_user_in_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Check whether a user is a member of a group.',
        operations=[{'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'HEAD'},
                    {'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'add_user_to_group',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Add user to group.',
        operations=[{'path': '/v3/groups/{group_id}/users/{user_id}',
                     'method': 'PUT'}])
]


def list_rules():
    return group_policies

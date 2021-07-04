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

SYSTEM_READER_OR_DOMAIN_READER_OR_USER = (
    '(' + base.SYSTEM_READER + ') or '
    '(role:reader and token.domain.id:%(target.user.domain_id)s) or '
    'user_id:%(target.user.id)s'
)

SYSTEM_READER_OR_DOMAIN_READER = (
    '(' + base.SYSTEM_READER + ') or (' + base.DOMAIN_READER + ')'
)

SYSTEM_ADMIN_OR_DOMAIN_ADMIN = (
    '(role:admin and system_scope:all) or '
    '(role:admin and token.domain.id:%(target.user.domain_id)s)'
)

DEPRECATED_REASON = (
    "The user API is now aware of system scope and default roles."
)

deprecated_get_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_user',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_users = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_users',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)

user_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_user',
        check_str=SYSTEM_READER_OR_DOMAIN_READER_OR_USER,
        scope_types=['system', 'domain', 'project'],
        description='Show user details.',
        operations=[{'path': '/v3/users/{user_id}',
                     'method': 'GET'},
                    {'path': '/v3/users/{user_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_user),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_users',
        check_str=SYSTEM_READER_OR_DOMAIN_READER,
        scope_types=['system', 'domain'],
        description='List users.',
        operations=[{'path': '/v3/users',
                     'method': 'GET'},
                    {'path': '/v3/users',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_users),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_projects_for_user',
        check_str='',
        # NOTE(lbragstad): We explicitly omit scope_types from this policy
        # because it's meant to be called with an unscoped token, which doesn't
        # apply to scope_types or its purpose. So long as the user is in the
        # system and has a valid token, they should be able to generate a list
        # of projects they have access to.
        description=('List all projects a user has access to via role '
                     'assignments.'),
        operations=[{'path': ' /v3/auth/projects',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_domains_for_user',
        check_str='',
        # NOTE(lbragstad): We explicitly omit scope_types from this policy
        # because it's meant to be called with an unscoped token, which doesn't
        # apply to scope_types or its purpose. So long as the user is in the
        # system and has a valid token, they should be able to generate a list
        # of domains they have access to.
        description=('List all domains a user has access to via role '
                     'assignments.'),
        operations=[{'path': '/v3/auth/domains',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_user',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description='Create a user.',
        operations=[{'path': '/v3/users',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_user),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_user',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description='Update a user, including administrative password resets.',
        operations=[{'path': '/v3/users/{user_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_user),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_user',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description='Delete a user.',
        operations=[{'path': '/v3/users/{user_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_user)
]


def list_rules():
    return user_policies

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

# Two of the three portions of this check string are specific to domain
# readers. The first catches domain readers who are checking or listing grants
# for users. The second does the same for groups. We have to overload the check
# string to handle both cases because `identity:check_grant` is used to protect
# both user and group grant APIs. If the `identity:check_grant` policy is every
# broken apart, we can write specific check strings that are tailored to either
# users or groups (e.g., `identity:check_group_grant` or
# `identity:check_user_grant`) and prevent overloading like this.
DOMAIN_MATCHES_USER_DOMAIN = 'domain_id:%(target.user.domain_id)s'
DOMAIN_MATCHES_GROUP_DOMAIN = 'domain_id:%(target.group.domain_id)s'
DOMAIN_MATCHES_PROJECT_DOMAIN = 'domain_id:%(target.project.domain_id)s'
DOMAIN_MATCHES_TARGET_DOMAIN = 'domain_id:%(target.domain.id)s'
DOMAIN_MATCHES_ROLE = (
    'domain_id:%(target.role.domain_id)s or None:%(target.role.domain_id)s'
)
GRANTS_DOMAIN_READER = (
    '(role:reader and ' + DOMAIN_MATCHES_USER_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_PROJECT_DOMAIN + ') or '
    '(role:reader and ' + DOMAIN_MATCHES_USER_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_TARGET_DOMAIN + ') or '
    '(role:reader and ' + DOMAIN_MATCHES_GROUP_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_PROJECT_DOMAIN + ') or '
    '(role:reader and ' + DOMAIN_MATCHES_GROUP_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_TARGET_DOMAIN + ')'
)
SYSTEM_READER_OR_DOMAIN_READER = (
    '(' + base.SYSTEM_READER + ') or '
    '(' + GRANTS_DOMAIN_READER + ') and '
    '(' + DOMAIN_MATCHES_ROLE + ')'
)

SYSTEM_READER_OR_DOMAIN_READER_LIST = (
    '(' + base.SYSTEM_READER + ') or ' + GRANTS_DOMAIN_READER
)

GRANTS_DOMAIN_ADMIN = (
    '(role:admin and ' + DOMAIN_MATCHES_USER_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_PROJECT_DOMAIN + ') or '
    '(role:admin and ' + DOMAIN_MATCHES_USER_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_TARGET_DOMAIN + ') or '
    '(role:admin and ' + DOMAIN_MATCHES_GROUP_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_PROJECT_DOMAIN + ') or '
    '(role:admin and ' + DOMAIN_MATCHES_GROUP_DOMAIN + ' and'
    ' ' + DOMAIN_MATCHES_TARGET_DOMAIN + ')'
)
SYSTEM_ADMIN_OR_DOMAIN_ADMIN = (
    '(' + base.SYSTEM_ADMIN + ') or '
    '(' + GRANTS_DOMAIN_ADMIN + ') and '
    '(' + DOMAIN_MATCHES_ROLE + ')'
)

DEPRECATED_REASON = (
    "The assignment API is now aware of system scope and default roles."
)

deprecated_check_system_grant_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_system_grant_for_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_system_grants_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_system_grants_for_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_system_grant_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_system_grant_for_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_revoke_system_grant_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_system_grant_for_user',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_check_system_grant_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_system_grant_for_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_system_grants_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_system_grants_for_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_system_grant_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_system_grant_for_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_revoke_system_grant_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_system_grant_for_group',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_grants = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_grants', check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_check_grant = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_grant', check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_grant = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_grant', check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_revoke_grant = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_grant', check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)


resource_paths = [
    '/projects/{project_id}/users/{user_id}/roles/{role_id}',
    '/projects/{project_id}/groups/{group_id}/roles/{role_id}',
    '/domains/{domain_id}/users/{user_id}/roles/{role_id}',
    '/domains/{domain_id}/groups/{group_id}/roles/{role_id}',
]


resource_paths += ['/OS-INHERIT' + path + '/inherited_to_projects'
                   for path in resource_paths]


collection_paths = [
    '/projects/{project_id}/users/{user_id}/roles',
    '/projects/{project_id}/groups/{group_id}/roles',
    '/domains/{domain_id}/users/{user_id}/roles',
    '/domains/{domain_id}/groups/{group_id}/roles'
]


inherited_collection_paths = [
    ('/OS-INHERIT/domains/{domain_id}/groups/{group_id}/roles/'
     'inherited_to_projects'),
    ('/OS-INHERIT/domains/{domain_id}/users/{user_id}/roles/'
     'inherited_to_projects')
]


def list_operations(paths, methods):
    return [{'path': '/v3' + path, 'method': method}
            for path in paths for method in methods]


# NOTE(samueldmq): Unlike individual resource paths, collection
# paths for the inherited grants do not contain a HEAD API
list_grants_operations = (
    list_operations(collection_paths, ['GET', 'HEAD']) +
    list_operations(inherited_collection_paths, ['GET']))


grant_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_grant',
        check_str=SYSTEM_READER_OR_DOMAIN_READER,
        scope_types=['system', 'domain'],
        description=('Check a role grant between a target and an actor. A '
                     'target can be either a domain or a project. An actor '
                     'can be either a user or a group. These terms also apply '
                     'to the OS-INHERIT APIs, where grants on the target '
                     'are inherited to all projects in the subtree, if '
                     'applicable.'),
        operations=list_operations(resource_paths, ['HEAD', 'GET']),
        deprecated_rule=deprecated_check_grant),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_grants',
        check_str=SYSTEM_READER_OR_DOMAIN_READER_LIST,
        scope_types=['system', 'domain'],
        description=('List roles granted to an actor on a target. A target '
                     'can be either a domain or a project. An actor can be '
                     'either a user or a group. For the OS-INHERIT APIs, it '
                     'is possible to list inherited role grants for actors on '
                     'domains, where grants are inherited to all projects '
                     'in the specified domain.'),
        operations=list_grants_operations,
        deprecated_rule=deprecated_list_grants),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_grant',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description=('Create a role grant between a target and an actor. A '
                     'target can be either a domain or a project. An actor '
                     'can be either a user or a group. These terms also apply '
                     'to the OS-INHERIT APIs, where grants on the target '
                     'are inherited to all projects in the subtree, if '
                     'applicable.'),
        operations=list_operations(resource_paths, ['PUT']),
        deprecated_rule=deprecated_create_grant),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_grant',
        check_str=SYSTEM_ADMIN_OR_DOMAIN_ADMIN,
        scope_types=['system', 'domain'],
        description=('Revoke a role grant between a target and an actor. A '
                     'target can be either a domain or a project. An actor '
                     'can be either a user or a group. These terms also apply '
                     'to the OS-INHERIT APIs, where grants on the target '
                     'are inherited to all projects in the subtree, if '
                     'applicable. In that case, revoking the role grant in '
                     'the target would remove the logical effect of '
                     'inheriting it to the target\'s projects subtree.'),
        operations=list_operations(resource_paths, ['DELETE']),
        deprecated_rule=deprecated_revoke_grant),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_system_grants_for_user',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List all grants a specific user has on the system.',
        operations=[
            {
                'path': '/v3/system/users/{user_id}/roles',
                'method': ['HEAD', 'GET']
            }
        ],
        deprecated_rule=deprecated_list_system_grants_for_user,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_system_grant_for_user',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Check if a user has a role on the system.',
        operations=[
            {
                'path': '/v3/system/users/{user_id}/roles/{role_id}',
                'method': ['HEAD', 'GET']
            }
        ],
        deprecated_rule=deprecated_check_system_grant_for_user,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_system_grant_for_user',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Grant a user a role on the system.',
        operations=[
            {
                'path': '/v3/system/users/{user_id}/roles/{role_id}',
                'method': ['PUT']
            }
        ],
        deprecated_rule=deprecated_create_system_grant_for_user,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_system_grant_for_user',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Remove a role from a user on the system.',
        operations=[
            {
                'path': '/v3/system/users/{user_id}/roles/{role_id}',
                'method': ['DELETE']
            }
        ],
        deprecated_rule=deprecated_revoke_system_grant_for_user,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_system_grants_for_group',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List all grants a specific group has on the system.',
        operations=[
            {
                'path': '/v3/system/groups/{group_id}/roles',
                'method': ['HEAD', 'GET']
            }
        ],
        deprecated_rule=deprecated_list_system_grants_for_group,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_system_grant_for_group',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Check if a group has a role on the system.',
        operations=[
            {
                'path': '/v3/system/groups/{group_id}/roles/{role_id}',
                'method': ['HEAD', 'GET']
            }
        ],
        deprecated_rule=deprecated_check_system_grant_for_group,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_system_grant_for_group',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Grant a group a role on the system.',
        operations=[
            {
                'path': '/v3/system/groups/{group_id}/roles/{role_id}',
                'method': ['PUT']
            }
        ],
        deprecated_rule=deprecated_create_system_grant_for_group,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_system_grant_for_group',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Remove a role from a group on the system.',
        operations=[
            {
                'path': '/v3/system/groups/{group_id}/roles/{role_id}',
                'method': ['DELETE']
            }
        ],
        deprecated_rule=deprecated_revoke_system_grant_for_group,
    )
]


def list_rules():
    return grant_policies

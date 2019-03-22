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

deprecated_check_system_grant_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_system_grant_for_user',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_list_system_grants_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_system_grants_for_user',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_create_system_grant_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_system_grant_for_user',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_revoke_system_grant_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_system_grant_for_user',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_check_system_grant_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_system_grant_for_group',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_list_system_grants_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_system_grants_for_group',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_create_system_grant_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_system_grant_for_group',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_revoke_system_grant_for_group = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_system_grant_for_group',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_list_grants = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_grants', check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_check_grant = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_grant', check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_create_grant = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_grant', check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_revoke_grant = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_grant', check_str=base.RULE_ADMIN_REQUIRED
)

DEPRECATED_REASON = """
As of the Stein release, the assignment API now understands default roles and
system-scoped tokens, making the API more granular by default without
compromising security. The new policy defaults account for these changes
automatically. Be sure to take these new defaults into consideration if you are
relying on overrides in your deployment for the system assignment API.
"""

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
        check_str=base.SYSTEM_READER,
        # FIXME(lbragstad): A system administrator should be able to grant role
        # assignments from any actor to any target in the deployment. Domain
        # administrators should only be able to grant access to the domain they
        # administer or projects within that domain. Once keystone is smart
        # enough to enforce those checks in code, we can add 'project' to the
        # list of scope_types below.
        scope_types=['system'],
        description=('Check a role grant between a target and an actor. A '
                     'target can be either a domain or a project. An actor '
                     'can be either a user or a group. These terms also apply '
                     'to the OS-INHERIT APIs, where grants on the target '
                     'are inherited to all projects in the subtree, if '
                     'applicable.'),
        operations=list_operations(resource_paths, ['HEAD', 'GET']),
        deprecated_rule=deprecated_check_grant,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_grants',
        check_str=base.SYSTEM_READER,
        # FIXME(lbragstad): See the above comment about scope_types before
        # adding 'project' to scope_types below.
        scope_types=['system'],
        description=('List roles granted to an actor on a target. A target '
                     'can be either a domain or a project. An actor can be '
                     'either a user or a group. For the OS-INHERIT APIs, it '
                     'is possible to list inherited role grants for actors on '
                     'domains, where grants are inherited to all projects '
                     'in the specified domain.'),
        operations=list_grants_operations,
        deprecated_rule=deprecated_list_grants,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_grant',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): See the above comment about scope_types before
        # adding 'project' to scope_types below.
        scope_types=['system'],
        description=('Create a role grant between a target and an actor. A '
                     'target can be either a domain or a project. An actor '
                     'can be either a user or a group. These terms also apply '
                     'to the OS-INHERIT APIs, where grants on the target '
                     'are inherited to all projects in the subtree, if '
                     'applicable.'),
        operations=list_operations(resource_paths, ['PUT']),
        deprecated_rule=deprecated_create_grant,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_grant',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): See the above comment about scope_types before
        # adding 'project' to scope_types below.
        scope_types=['system'],
        description=('Revoke a role grant between a target and an actor. A '
                     'target can be either a domain or a project. An actor '
                     'can be either a user or a group. These terms also apply '
                     'to the OS-INHERIT APIs, where grants on the target '
                     'are inherited to all projects in the subtree, if '
                     'applicable. In that case, revoking the role grant in '
                     'the target would remove the logical effect of '
                     'inheriting it to the target\'s projects subtree.'),
        operations=list_operations(resource_paths, ['DELETE']),
        deprecated_rule=deprecated_revoke_grant,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
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
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
    )
]


def list_rules():
    return grant_policies

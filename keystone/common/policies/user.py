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

# Allow access for system readers or users attempting to list their owner user
# reference.
SYSTEM_READER_OR_USER = (
    '(' + base.SYSTEM_READER + ') or user_id:%(target.user.id)s'
)

DEPRECATED_REASON = """
As of the Stein release, the user API understands how to handle system-scoped
tokens in addition to project and domain tokens, making the API more accessible
to users without compromising security or manageability for administrators. The
new default policies for this API account for these changes automatically.
"""

deprecated_get_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_user',
    check_str=base.RULE_ADMIN_OR_OWNER
)
deprecated_list_users = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_users',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_create_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_user',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_update_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_user',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_delete_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_user',
    check_str=base.RULE_ADMIN_REQUIRED
)

user_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_user',
        check_str=SYSTEM_READER_OR_USER,
        scope_types=['system', 'project'],
        description='Show user details.',
        operations=[{'path': '/v3/users/{user_id}',
                     'method': 'GET'},
                    {'path': '/v3/users/{user_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_user,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_users',
        check_str=base.SYSTEM_READER,
        # FIXME(lbragstad): Since listing users has traditionally always been a
        # system-level API call, let's maintain that pattern here. A system
        # administrator should be able to list all users in the deployment,
        # which is what's supported today. Project and domain administrators
        # should also be able to list users, but they should only see users
        # within their project or domain. Otherwise it would be possible for
        # project and domain administrators to see users unrelated to their
        # project or domain, which would be a security issue. Once we have that
        # support in place, we should update scope_types to include 'project'.
        scope_types=['system'],
        description='List users.',
        operations=[{'path': '/v3/users',
                     'method': 'GET'},
                    {'path': '/v3/users',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_users,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
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
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): This can be considered either a system-level policy
        # or a project-level policy. System administrator should have the
        # ability to create users in any domain. Domain (or project)
        # administrators should have the ability to create users in the domain
        # they administer. The second case is going to require a policy check
        # in code. Until that happens, we will leave this as a system-level
        # policy.
        scope_types=['system'],
        description='Create a user.',
        operations=[{'path': '/v3/users',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_user,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_user',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): See the above comment about adding support for
        # project scope_types in the future.
        scope_types=['system'],
        description='Update a user, including administrative password resets.',
        operations=[{'path': '/v3/users/{user_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_user,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_user',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): See the above comment about adding support for
        # project scope_types in the future.
        scope_types=['system'],
        description='Delete a user.',
        operations=[{'path': '/v3/users/{user_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_user,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN)
]


def list_rules():
    return user_policies

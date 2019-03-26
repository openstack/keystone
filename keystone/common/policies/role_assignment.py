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

SYSTEM_READER_OR_DOMAIN_READER = (
    '(' + base.SYSTEM_READER + ') or '
    '(role:reader and domain_id:%(target.domain_id)s)'
)

deprecated_list_role_assignments = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_role_assignments',
    check_str=base.RULE_ADMIN_REQUIRED
)

DEPRECATED_REASON = """
As of the Stein release, the role assignment API now understands how to
handle system-scoped tokens in addition to project-scoped tokens, making
the API more accessible to users without compromising security or
manageability for administrators. The new default policies for this API
account for these changes automatically.
"""

role_assignment_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_role_assignments',
        check_str=SYSTEM_READER_OR_DOMAIN_READER,
        scope_types=['system', 'domain'],
        description='List role assignments.',
        operations=[{'path': '/v3/role_assignments',
                     'method': 'GET'},
                    {'path': '/v3/role_assignments',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_role_assignments,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_role_assignments_for_tree',
        check_str=base.RULE_ADMIN_REQUIRED,
        # NOTE(lbragstad): This is purely a project-scoped operation. The
        # project tree is calculated based on the project scope of the token
        # used to make the request. System administrators would have to find a
        # way to supply a project scope with a system-scoped token, which
        # defeats the purpose. System administrators can list all role
        # assignments anyway, so the usefulness of an API that returns a subset
        # is negligible when they have access to the entire set.
        scope_types=['project'],
        description=('List all role assignments for a given tree of '
                     'hierarchical projects.'),
        operations=[{'path': '/v3/role_assignments?include_subtree',
                     'method': 'GET'},
                    {'path': '/v3/role_assignments?include_subtree',
                     'method': 'HEAD'}])
]


def list_rules():
    return role_assignment_policies

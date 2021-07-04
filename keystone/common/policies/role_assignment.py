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
SYSTEM_READER_OR_PROJECT_DOMAIN_READER_OR_PROJECT_ADMIN = (
    '(' + base.SYSTEM_READER + ') or '
    '(role:reader and domain_id:%(target.project.domain_id)s) or '
    '(role:admin and project_id:%(target.project.id)s)'
)

DEPRECATED_REASON = (
    "The assignment API is now aware of system scope and default roles."
)

deprecated_list_role_assignments = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_role_assignments',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_role_assignments_for_tree = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_role_assignments_for_tree',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


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
        deprecated_rule=deprecated_list_role_assignments),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_role_assignments_for_tree',
        check_str=SYSTEM_READER_OR_PROJECT_DOMAIN_READER_OR_PROJECT_ADMIN,
        scope_types=['system', 'domain', 'project'],
        description=('List all role assignments for a given tree of '
                     'hierarchical projects.'),
        operations=[{'path': '/v3/role_assignments?include_subtree',
                     'method': 'GET'},
                    {'path': '/v3/role_assignments?include_subtree',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_role_assignments_for_tree),

]


def list_rules():
    return role_assignment_policies

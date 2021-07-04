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

DEPRECATED_REASON = """
As of the Train release, the project endpoint API now understands default
roles and system-scoped tokens, making the API more granular by default without
compromising security. The new policy defaults account for these changes
automatically. Be sure to take these new defaults into consideration if you are
relying on overrides in your deployment for the project endpoint API.
"""

deprecated_list_projects_for_endpoint = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_projects_for_endpoint',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_add_endpoint_to_project = policy.DeprecatedRule(
    name=base.IDENTITY % 'add_endpoint_to_project',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_check_endpoint_in_project = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_endpoint_in_project',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_list_endpoints_for_project = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_endpoints_for_project',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_remove_endpoint_from_project = policy.DeprecatedRule(
    name=base.IDENTITY % 'remove_endpoint_from_project',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


project_endpoint_policies = [

    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_projects_for_endpoint',
        check_str=base.SYSTEM_READER,
        # NOTE(lbragstad): While projects can be considered project-level APIs
        # with hierarchical multi-tenancy, endpoints are a system-level
        # resource. Managing associations between projects and endpoints should
        # default to system-level.
        scope_types=['system'],
        description='List projects allowed to access an endpoint.',
        operations=[{'path': ('/v3/OS-EP-FILTER/endpoints/{endpoint_id}/'
                              'projects'),
                     'method': 'GET'}],
        deprecated_rule=deprecated_list_projects_for_endpoint),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'add_endpoint_to_project',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Allow project to access an endpoint.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'PUT'}],
        deprecated_rule=deprecated_add_endpoint_to_project),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_endpoint_in_project',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Check if a project is allowed to access an endpoint.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_check_endpoint_in_project),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_endpoints_for_project',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List the endpoints a project is allowed to access.',
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints'),
                     'method': 'GET'}],
        deprecated_rule=deprecated_list_endpoints_for_project),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'remove_endpoint_from_project',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=('Remove access to an endpoint from a project that has '
                     'previously been given explicit access.'),
        operations=[{'path': ('/v3/OS-EP-FILTER/projects/{project_id}/'
                              'endpoints/{endpoint_id}'),
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_remove_endpoint_from_project),
]


def list_rules():
    return project_endpoint_policies

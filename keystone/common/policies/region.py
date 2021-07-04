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
    "The region API is now aware of system scope and default roles."
)

deprecated_create_region = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_region',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_region = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_region',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_region = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_region',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)


region_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_region',
        check_str='',
        # NOTE(lbragstad): Both get_region and list_regions were accessible
        # with a valid token. By including both `system` and `project`
        # scope types, we're ensuring anyone with a valid token can still
        # pass these policies. Since the administrative policies of regions
        # require and administrator, it makes sense to isolate those to
        # `system` scope.
        scope_types=['system', 'domain', 'project'],
        description='Show region details.',
        operations=[{'path': '/v3/regions/{region_id}',
                     'method': 'GET'},
                    {'path': '/v3/regions/{region_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_regions',
        check_str='',
        scope_types=['system', 'domain', 'project'],
        description='List regions.',
        operations=[{'path': '/v3/regions',
                     'method': 'GET'},
                    {'path': '/v3/regions',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_region',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Create region.',
        operations=[{'path': '/v3/regions',
                     'method': 'POST'},
                    {'path': '/v3/regions/{region_id}',
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_region),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_region',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update region.',
        operations=[{'path': '/v3/regions/{region_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_region),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_region',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete region.',
        operations=[{'path': '/v3/regions/{region_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_region),
]


def list_rules():
    return region_policies

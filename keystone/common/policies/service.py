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
    "The service API is now aware of system scope and default roles."
)

deprecated_get_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_services',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)


service_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_service',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Show service details.',
        operations=[{'path': '/v3/services/{service_id}',
                     'method': 'GET'}],
        deprecated_rule=deprecated_get_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_services',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List services.',
        operations=[{'path': '/v3/services',
                     'method': 'GET'}],
        deprecated_rule=deprecated_list_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_service',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Create service.',
        operations=[{'path': '/v3/services',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_service',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update service.',
        operations=[{'path': '/v3/services/{service_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_service',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete service.',
        operations=[{'path': '/v3/services/{service_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_service)
]


def list_rules():
    return service_policies

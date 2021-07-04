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

# NOTE(lbragstad): Both endpoints and services are system-level resources.
# System-scoped tokens should be required to manage policy associations to
# existing system-level resources.

DEPRECATED_REASON = (
    "The policy association API is now aware of system scope and default "
    "roles."
)

deprecated_check_policy_assoc_for_endpoint = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_policy_association_for_endpoint',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_check_policy_assoc_for_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_policy_association_for_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_check_policy_assoc_for_region_and_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_policy_association_for_region_and_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_get_policy_for_endpoint = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_policy_for_endpoint',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_list_endpoints_for_policy = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_endpoints_for_policy',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_create_policy_assoc_for_endpoint = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_policy_association_for_endpoint',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_delete_policy_assoc_for_endpoint = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_policy_association_for_endpoint',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_create_policy_assoc_for_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_policy_association_for_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_delete_policy_assoc_for_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_policy_association_for_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_create_policy_assoc_for_region_and_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_policy_association_for_region_and_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_delete_policy_assoc_for_region_and_service = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_policy_association_for_region_and_service',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


policy_association_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_policy_association_for_endpoint',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Associate a policy to a specific endpoint.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'endpoints/{endpoint_id}'),
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_policy_assoc_for_endpoint),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_policy_association_for_endpoint',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Check policy association for endpoint.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'endpoints/{endpoint_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'endpoints/{endpoint_id}'),
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_check_policy_assoc_for_endpoint),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_policy_association_for_endpoint',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete policy association for endpoint.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'endpoints/{endpoint_id}'),
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_policy_assoc_for_endpoint),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_policy_association_for_service',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Associate a policy to a specific service.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}'),
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_policy_assoc_for_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_policy_association_for_service',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Check policy association for service.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}'),
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_check_policy_assoc_for_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_policy_association_for_service',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete policy association for service.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}'),
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_policy_assoc_for_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % (
            'create_policy_association_for_region_and_service'),
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=('Associate a policy to a specific region and service '
                     'combination.'),
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}/regions/{region_id}'),
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_policy_assoc_for_region_and_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_policy_association_for_region_and_service',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Check policy association for region and service.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}/regions/{region_id}'),
                     'method': 'GET'},
                    {'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}/regions/{region_id}'),
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_check_policy_assoc_for_region_and_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % (
            'delete_policy_association_for_region_and_service'),
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete policy association for region and service.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'services/{service_id}/regions/{region_id}'),
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_policy_assoc_for_region_and_service),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_policy_for_endpoint',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get policy for endpoint.',
        operations=[{'path': ('/v3/endpoints/{endpoint_id}/OS-ENDPOINT-POLICY/'
                              'policy'),
                     'method': 'GET'},
                    {'path': ('/v3/endpoints/{endpoint_id}/OS-ENDPOINT-POLICY/'
                              'policy'),
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_policy_for_endpoint),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_endpoints_for_policy',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List endpoints for policy.',
        operations=[{'path': ('/v3/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                              'endpoints'),
                     'method': 'GET'}],
        deprecated_rule=deprecated_list_endpoints_for_policy)
]


def list_rules():
    return policy_association_policies

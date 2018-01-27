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

from oslo_policy import policy

from keystone.common.policies import base

service_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_service',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Show service details.',
        operations=[{'path': '/v3/services/{service_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_services',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List services.',
        operations=[{'path': '/v3/services',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_service',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create service.',
        operations=[{'path': '/v3/services',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_service',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update service.',
        operations=[{'path': '/v3/services/{service_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_service',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete service.',
        operations=[{'path': '/v3/services/{service_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return service_policies

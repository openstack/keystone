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

policy_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_policy',
        check_str=base.RULE_ADMIN_REQUIRED,
        # This API isn't really exposed to usable, it's actually deprecated.
        # More-or-less adding scope_types to be consistent with other policies.
        scope_types=['system'],
        description='Show policy details.',
        operations=[{'path': '/v3/policy/{policy_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_policies',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List policies.',
        operations=[{'path': '/v3/policies',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_policy',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create policy.',
        operations=[{'path': '/v3/policies',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_policy',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update policy.',
        operations=[{'path': '/v3/policies/{policy_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_policy',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete policy.',
        operations=[{'path': '/v3/policies/{policy_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return policy_policies

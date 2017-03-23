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

token_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_token',
        check_str=base.RULE_ADMIN_OR_TOKEN_SUBJECT,
        description='Check a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'validate_token',
        check_str=base.RULE_SERVICE_ADMIN_OR_TOKEN_SUBJECT,
        description='Validate a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'GET'},
                    {'path': '/v2.0/tokens/{token_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'validate_token_head',
        check_str=base.RULE_SERVICE_OR_ADMIN,
        description='Validate a token.',
        operations=[{'path': '/v2.0/tokens/{token_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_token',
        check_str=base.RULE_ADMIN_OR_TOKEN_SUBJECT,
        description='Revoke a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'DELETE'}])
]


def list_rules():
    return token_policies

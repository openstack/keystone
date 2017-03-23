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

credential_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Show credentials details.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_credentials',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='List credentials.',
        operations=[{'path': '/v3/credentials',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Create credential.',
        operations=[{'path': '/v3/credentials',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Update credential.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        description='Delete credential.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return credential_policies

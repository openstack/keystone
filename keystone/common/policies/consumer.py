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

consumer_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_consumer',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Show OAUTH1 consumer details.',
        operations=[{'path': '/v3/OS-OAUTH1/consumers/{consumer_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_consumers',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List OAUTH1 consumers.',
        operations=[{'path': '/v3/OS-OAUTH1/consumers',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_consumer',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create OAUTH1 consumer.',
        operations=[{'path': '/v3/OS-OAUTH1/consumers',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_consumer',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update OAUTH1 consumer.',
        operations=[{'path': '/v3/OS-OAUTH1/consumers/{consumer_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_consumer',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete OAUTH1 consumer.',
        operations=[{'path': '/v3/OS-OAUTH1/consumers/{consumer_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return consumer_policies

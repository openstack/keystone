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

registered_limit_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_registered_limit',
        check_str='',
        scope_types=['system', 'domain', 'project'],
        description='Show registered limit details.',
        operations=[{'path': '/v3/registered_limits/{registered_limit_id}',
                     'method': 'GET'},
                    {'path': '/v3/registered_limits/{registered_limit_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_registered_limits',
        check_str='',
        scope_types=['system', 'domain', 'project'],
        description='List registered limits.',
        operations=[{'path': '/v3/registered_limits',
                     'method': 'GET'},
                    {'path': '/v3/registered_limits',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_registered_limits',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Create registered limits.',
        operations=[{'path': '/v3/registered_limits',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_registered_limit',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update registered limit.',
        operations=[{'path': '/v3/registered_limits/{registered_limit_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_registered_limit',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete registered limit.',
        operations=[{'path': '/v3/registered_limits/{registered_limit_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return registered_limit_policies

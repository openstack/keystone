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

limit_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_limit_model',
        check_str='',
        scope_types=['system', 'project'],
        description='Get limit enforcement model.',
        operations=[{'path': '/v3/limits/model',
                     'method': 'GET'},
                    {'path': '/v3/limits/model',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_limit',
        check_str='(role:reader and system_scope:all) or '
                  'project_id:%(target.limit.project_id)s or '
                  'domain_id:%(target.limit.domain_id)s',
        scope_types=['system', 'project', 'domain'],
        description='Show limit details.',
        operations=[{'path': '/v3/limits/{limit_id}',
                     'method': 'GET'},
                    {'path': '/v3/limits/{limit_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_limits',
        check_str='',
        scope_types=['system', 'project'],
        description='List limits.',
        operations=[{'path': '/v3/limits',
                     'method': 'GET'},
                    {'path': '/v3/limits',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_limits',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Create limits.',
        operations=[{'path': '/v3/limits',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_limit',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update limit.',
        operations=[{'path': '/v3/limits/{limit_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_limit',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete limit.',
        operations=[{'path': '/v3/limits/{limit_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return limit_policies

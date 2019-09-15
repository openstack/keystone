# Copyright 2019 SUSE LLC
#
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

collection_path = '/v3/users/{user_id}/access_rules'
resource_path = collection_path + '/{access_rule_id}'

SYSTEM_READER_OR_OWNER = (
    '(' + base.SYSTEM_READER + ') or '
    'user_id:%(target.user.id)s'
)

SYSTEM_ADMIN_OR_OWNER = (
    '(' + base.SYSTEM_ADMIN + ') or '
    'user_id:%(target.user.id)s'
)

access_rule_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_access_rule',
        check_str=SYSTEM_READER_OR_OWNER,
        scope_types=['system', 'project'],
        description='Show access rule details.',
        operations=[{'path': resource_path,
                     'method': 'GET'},
                    {'path': resource_path,
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_access_rules',
        check_str=SYSTEM_READER_OR_OWNER,
        scope_types=['system', 'project'],
        description='List access rules for a user.',
        operations=[{'path': collection_path,
                     'method': 'GET'},
                    {'path': collection_path,
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_access_rule',
        check_str=SYSTEM_ADMIN_OR_OWNER,
        scope_types=['system', 'project'],
        description='Delete an access_rule.',
        operations=[{'path': resource_path,
                     'method': 'DELETE'}])
]


def list_rules():
    return access_rule_policies

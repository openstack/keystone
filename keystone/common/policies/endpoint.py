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

endpoint_policies = [
    policy.RuleDefault(
        name=base.IDENTITY % 'get_endpoint',
        check_str=base.RULE_ADMIN_REQUIRED),
    policy.RuleDefault(
        name=base.IDENTITY % 'list_endpoints',
        check_str=base.RULE_ADMIN_REQUIRED),
    policy.RuleDefault(
        name=base.IDENTITY % 'create_endpoint',
        check_str=base.RULE_ADMIN_REQUIRED),
    policy.RuleDefault(
        name=base.IDENTITY % 'update_endpoint',
        check_str=base.RULE_ADMIN_REQUIRED),
    policy.RuleDefault(
        name=base.IDENTITY % 'delete_endpoint',
        check_str=base.RULE_ADMIN_REQUIRED)
]


def list_rules():
    return endpoint_policies

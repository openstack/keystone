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

ec2_credential_policies = [
    policy.RuleDefault(
        name=base.IDENTITY % 'ec2_get_credential',
        check_str=base.RULE_ADMIN_OR_CREDENTIAL_OWNER),
    policy.RuleDefault(
        name=base.IDENTITY % 'ec2_list_credentials',
        check_str=base.RULE_ADMIN_OR_OWNER),
    policy.RuleDefault(
        name=base.IDENTITY % 'ec2_create_credential',
        check_str=base.RULE_ADMIN_OR_OWNER),
    policy.RuleDefault(
        name=base.IDENTITY % 'ec2_delete_credential',
        check_str=base.RULE_ADMIN_OR_CREDENTIAL_OWNER),
]


def list_rules():
    return ec2_credential_policies

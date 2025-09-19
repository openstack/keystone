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

# Align EC2 tokens API with S3 tokens: require admin or service users
ADMIN_OR_SERVICE = 'rule:service_or_admin'


ec2tokens_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2tokens_validate',
        check_str=ADMIN_OR_SERVICE,
        scope_types=['system', 'domain', 'project'],
        description='Validate EC2 credentials and create a Keystone token. '
        'Restricted to service users or administrators.',
        operations=[{'path': '/v3/ec2tokens', 'method': 'POST'}],
    )
]


def list_rules():
    return ec2tokens_policies

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

# S3 tokens API requires service authentication to prevent presigned URL
# exploitation.
# This policy restricts access to service users or administrators only
ADMIN_OR_SERVICE = 'rule:service_or_admin'

s3tokens_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 's3tokens_validate',
        check_str=ADMIN_OR_SERVICE,
        scope_types=['system', 'domain', 'project'],
        description='Validate S3 credentials and create a Keystone token. '
        'Restricted to service users or administrators to prevent '
        'exploitation via presigned URLs.',
        operations=[{'path': '/v3/s3tokens', 'method': 'POST'}],
    )
]


def list_rules():
    return s3tokens_policies

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

from oslo_log import versionutils
from oslo_policy import policy

from keystone.common.policies import base

DEPRECATED_REASON = (
    "The EC2 credential API is now aware of system scope and default roles."
)

deprecated_ec2_get_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'ec2_get_credential',
    check_str=base.RULE_ADMIN_OR_CREDENTIAL_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_ec2_list_credentials = policy.DeprecatedRule(
    name=base.IDENTITY % 'ec2_list_credentials',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_ec2_create_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'ec2_create_credential',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_ec2_delete_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'ec2_delete_credential',
    check_str=base.RULE_ADMIN_OR_CREDENTIAL_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


ec2_credential_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_get_credential',
        check_str=base.SYSTEM_READER_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='Show ec2 credential details.',
        operations=[{'path': ('/v3/users/{user_id}/credentials/OS-EC2/'
                              '{credential_id}'),
                     'method': 'GET'}],
        deprecated_rule=deprecated_ec2_get_credential
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_list_credentials',
        check_str=base.RULE_SYSTEM_READER_OR_OWNER,
        scope_types=['system', 'project'],
        description='List ec2 credentials.',
        operations=[{'path': '/v3/users/{user_id}/credentials/OS-EC2',
                     'method': 'GET'}],
        deprecated_rule=deprecated_ec2_list_credentials,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_create_credential',
        check_str=base.RULE_SYSTEM_ADMIN_OR_OWNER,
        scope_types=['system', 'project'],
        description='Create ec2 credential.',
        operations=[{'path': '/v3/users/{user_id}/credentials/OS-EC2',
                     'method': 'POST'}],
        deprecated_rule=deprecated_ec2_create_credential,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_delete_credential',
        check_str=base.SYSTEM_ADMIN_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='Delete ec2 credential.',
        operations=[{'path': ('/v3/users/{user_id}/credentials/OS-EC2/'
                              '{credential_id}'),
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_ec2_delete_credential,
    )
]


def list_rules():
    return ec2_credential_policies

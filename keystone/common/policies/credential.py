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
    "The credential API is now aware of system scope and default roles."
)

deprecated_get_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_credential',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_credentials = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_credentials',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_credential',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_credential',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_credential = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_credential',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)


credential_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_credential',
        check_str=base.SYSTEM_READER_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='Show credentials details.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'GET'}],
        deprecated_rule=deprecated_get_credential,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_credentials',
        check_str=base.SYSTEM_READER_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='List credentials.',
        operations=[{'path': '/v3/credentials',
                     'method': 'GET'}],
        deprecated_rule=deprecated_list_credentials,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_credential',
        check_str=base.SYSTEM_ADMIN_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='Create credential.',
        operations=[{'path': '/v3/credentials',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_credential,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_credential',
        check_str=base.SYSTEM_ADMIN_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='Update credential.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_credential,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_credential',
        check_str=base.SYSTEM_ADMIN_OR_CRED_OWNER,
        scope_types=['system', 'project'],
        description='Delete credential.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_credential,
    )
]


def list_rules():
    return credential_policies

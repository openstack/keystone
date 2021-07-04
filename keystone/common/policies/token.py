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
    "The token API is now aware of system scope and default roles."
)

deprecated_check_token = policy.DeprecatedRule(
    name=base.IDENTITY % 'check_token',
    check_str=base.RULE_ADMIN_OR_TOKEN_SUBJECT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_validate_token = policy.DeprecatedRule(
    name=base.IDENTITY % 'validate_token',
    check_str=base.RULE_SERVICE_ADMIN_OR_TOKEN_SUBJECT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_revoke_token = policy.DeprecatedRule(
    name=base.IDENTITY % 'revoke_token',
    check_str=base.RULE_ADMIN_OR_TOKEN_SUBJECT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

SYSTEM_ADMIN_OR_TOKEN_SUBJECT = (
    '(role:admin and system_scope:all) or rule:token_subject'  # nosec
)
SYSTEM_USER_OR_TOKEN_SUBJECT = (
    '(role:reader and system_scope:all) or rule:token_subject'  # nosec
)
SYSTEM_USER_OR_SERVICE_OR_TOKEN_SUBJECT = (
    '(role:reader and system_scope:all) '  # nosec
    'or rule:service_role or rule:token_subject'  # nosec
)


token_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_token',
        check_str=SYSTEM_USER_OR_TOKEN_SUBJECT,
        scope_types=['system', 'domain', 'project'],
        description='Check a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_check_token),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'validate_token',
        check_str=SYSTEM_USER_OR_SERVICE_OR_TOKEN_SUBJECT,
        scope_types=['system', 'domain', 'project'],
        description='Validate a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'GET'}],
        deprecated_rule=deprecated_validate_token),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_token',
        check_str=SYSTEM_ADMIN_OR_TOKEN_SUBJECT,
        scope_types=['system', 'domain', 'project'],
        description='Revoke a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_revoke_token)
]


def list_rules():
    return token_policies

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

RULE_TRUSTOR = 'user_id:%(target.trust.trustor_user_id)s'
RULE_TRUSTEE = 'user_id:%(target.trust.trustee_user_id)s'
SYSTEM_READER_OR_TRUSTOR_OR_TRUSTEE = (
    base.SYSTEM_READER + ' or ' + RULE_TRUSTOR + ' or ' + RULE_TRUSTEE
)
SYSTEM_READER_OR_TRUSTOR = base.SYSTEM_READER + ' or ' + RULE_TRUSTOR
SYSTEM_READER_OR_TRUSTEE = base.SYSTEM_READER + ' or ' + RULE_TRUSTEE
SYSTEM_ADMIN_OR_TRUSTOR = base.SYSTEM_ADMIN + ' or ' + RULE_TRUSTOR

DEPRECATED_REASON = (
    "The trust API is now aware of system scope and default roles."
)

deprecated_list_trusts = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_trusts',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_list_roles_for_trust = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_roles_for_trust',
    check_str=RULE_TRUSTOR + ' or ' + RULE_TRUSTEE,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_get_role_for_trust = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_role_for_trust',
    check_str=RULE_TRUSTOR + ' or ' + RULE_TRUSTEE,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_delete_trust = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_trust',
    check_str=RULE_TRUSTOR,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_get_trust = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_trust',
    check_str=RULE_TRUSTOR + ' or ' + RULE_TRUSTEE,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

trust_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_trust',
        check_str=base.RULE_TRUST_OWNER,
        # FIXME(lbragstad): Trusts have the ability to optionally include a
        # project, but until trusts deal with system scope it's not really
        # useful. For now, this should be a project only operation.
        scope_types=['project'],
        description='Create trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_trusts',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List trusts.',
        operations=[{'path': '/v3/OS-TRUST/trusts',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_trusts),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_trusts_for_trustor',
        check_str=SYSTEM_READER_OR_TRUSTOR,
        scope_types=['system', 'project'],
        description='List trusts for trustor.',
        operations=[{'path': '/v3/OS-TRUST/trusts?'
                             'trustor_user_id={trustor_user_id}',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts?'
                             'trustor_user_id={trustor_user_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_trusts_for_trustee',
        check_str=SYSTEM_READER_OR_TRUSTEE,
        scope_types=['system', 'project'],
        description='List trusts for trustee.',
        operations=[{'path': '/v3/OS-TRUST/trusts?'
                             'trustee_user_id={trustee_user_id}',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts?'
                             'trustee_user_id={trustee_user_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_roles_for_trust',
        check_str=SYSTEM_READER_OR_TRUSTOR_OR_TRUSTEE,
        scope_types=['system', 'project'],
        description='List roles delegated by a trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}/roles',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts/{trust_id}/roles',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_roles_for_trust),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_role_for_trust',
        check_str=SYSTEM_READER_OR_TRUSTOR_OR_TRUSTEE,
        scope_types=['system', 'project'],
        description='Check if trust delegates a particular role.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_role_for_trust),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_trust',
        check_str=SYSTEM_ADMIN_OR_TRUSTOR,
        scope_types=['system', 'project'],
        description='Revoke trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_trust),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_trust',
        check_str=SYSTEM_READER_OR_TRUSTOR_OR_TRUSTEE,
        scope_types=['system', 'project'],
        description='Get trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts/{trust_id}',
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_trust)
]


def list_rules():
    return trust_policies

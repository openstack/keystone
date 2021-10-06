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
    "The identity provider API is now aware of system scope and default roles."
)

deprecated_get_idp = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_identity_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_idp = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_identity_providers',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_idp = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_identity_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_idp = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_identity_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_idp = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_identity_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)


identity_provider_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_identity_provider',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): All `scope_types` for identity provider policies
        # should be updated to include project scope if, or when, it becomes
        # possible to manage federated identity providers without modifying
        # configurations outside of keystone (Apache). It makes sense to
        # associate system scope to identity provider management since it
        # requires modifying configuration files.
        scope_types=['system'],
        description='Create identity provider.',
        operations=[{'path': '/v3/OS-FEDERATION/identity_providers/{idp_id}',
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_idp),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_identity_providers',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List identity providers.',
        operations=[
            {
                'path': '/v3/OS-FEDERATION/identity_providers',
                'method': 'GET'
            },
            {
                'path': '/v3/OS-FEDERATION/identity_providers',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_list_idp,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_identity_provider',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get identity provider.',
        operations=[
            {
                'path': '/v3/OS-FEDERATION/identity_providers/{idp_id}',
                'method': 'GET'
            },
            {
                'path': '/v3/OS-FEDERATION/identity_providers/{idp_id}',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_get_idp,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_identity_provider',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update identity provider.',
        operations=[{'path': '/v3/OS-FEDERATION/identity_providers/{idp_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_idp),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_identity_provider',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete identity provider.',
        operations=[{'path': '/v3/OS-FEDERATION/identity_providers/{idp_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_idp),
]


def list_rules():
    return identity_provider_policies

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

deprecated_get_mapping = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_mapping',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_list_mappings = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_mappings',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_update_mapping = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_mapping',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_create_mapping = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_mapping',
    check_str=base.RULE_ADMIN_REQUIRED
)
deprecated_delete_mapping = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_mapping',
    check_str=base.RULE_ADMIN_REQUIRED
)

DEPRECATED_REASON = """
As of the Stein release, the federated mapping API now understands default
roles and system-scoped tokens, making the API more granular by default without
compromising security. The new policy defaults account for these changes
automatically. Be sure to take these new defaults into consideration if you are
relying on overrides in your deployment for the federated mapping API.
"""

mapping_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_mapping',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): Today, keystone doesn't support federation unless
        # the person create identity providers, service providers, or mappings
        # has the ability to modify keystone and Apache configuration files.
        # If, or when, keystone adds support for federating identities without
        # having to touch system configuration files, the list of `scope_types`
        # for these policies should include `project`.
        scope_types=['system'],
        description=('Create a new federated mapping containing one or '
                     'more sets of rules.'),
        operations=[{'path': '/v3/OS-FEDERATION/mappings/{mapping_id}',
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_mapping,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_mapping',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get a federated mapping.',
        operations=[
            {
                'path': '/v3/OS-FEDERATION/mappings/{mapping_id}',
                'method': 'GET'
            },
            {
                'path': '/v3/OS-FEDERATION/mappings/{mapping_id}',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_get_mapping,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_mappings',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List federated mappings.',
        operations=[
            {
                'path': '/v3/OS-FEDERATION/mappings',
                'method': 'GET'
            },
            {
                'path': '/v3/OS-FEDERATION/mappings',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_get_mapping,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_mapping',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete a federated mapping.',
        operations=[{'path': '/v3/OS-FEDERATION/mappings/{mapping_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_mapping,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_mapping',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update a federated mapping.',
        operations=[{'path': '/v3/OS-FEDERATION/mappings/{mapping_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_mapping,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.STEIN)
]


def list_rules():
    return mapping_policies

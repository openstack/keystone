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
    "The domain API is now aware of system scope and default roles."
)

deprecated_list_domains = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_domains',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_get_domain = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_domain',
    check_str=base.RULE_ADMIN_OR_TARGET_DOMAIN,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_domain = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_domain',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_domain = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_domain',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_domain = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_domain',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
SYSTEM_USER_OR_DOMAIN_USER_OR_PROJECT_USER = (
    '(role:reader and system_scope:all) or '
    'token.domain.id:%(target.domain.id)s or '
    'token.project.domain.id:%(target.domain.id)s'
)


domain_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_domain',
        # NOTE(lbragstad): This policy allows system, domain, and
        # project-scoped tokens.
        check_str=SYSTEM_USER_OR_DOMAIN_USER_OR_PROJECT_USER,
        scope_types=['system', 'domain', 'project'],
        description='Show domain details.',
        operations=[{'path': '/v3/domains/{domain_id}',
                     'method': 'GET'}],
        deprecated_rule=deprecated_get_domain),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_domains',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List domains.',
        operations=[{'path': '/v3/domains',
                     'method': 'GET'}],
        deprecated_rule=deprecated_list_domains),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_domain',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Create domain.',
        operations=[{'path': '/v3/domains',
                     'method': 'POST'}],
        deprecated_rule=deprecated_create_domain),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_domain',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update domain.',
        operations=[{'path': '/v3/domains/{domain_id}',
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_domain),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_domain',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete domain.',
        operations=[{'path': '/v3/domains/{domain_id}',
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_domain),
]


def list_rules():
    return domain_policies

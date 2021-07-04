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
    "The domain config API is now aware of system scope and default roles."
)

deprecated_get_domain_config = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_domain_config',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_get_domain_config_default = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_domain_config_default',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_create_domain_config = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_domain_config',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_update_domain_config = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_domain_config',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)

deprecated_delete_domain_config = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_domain_config',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


domain_config_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_domain_config',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): The domain configuration API has traditionally
        # required system or cloud administrators. If, or when, keystone
        # implements the ability for project administrator to use these APIs,
        # then 'project' should be added to scope_types. Adding support for
        # project or domain administrator to manage their own domain
        # configuration would be useful and alleviate work for system
        # administrators, but until we have checks in code that enforce those
        # checks, let's keep this as a system-level operation.
        scope_types=['system'],
        description='Create domain configuration.',
        operations=[
            {
                'path': '/v3/domains/{domain_id}/config',
                'method': 'PUT'
            }
        ],
        deprecated_rule=deprecated_create_domain_config
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_domain_config',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description=('Get the entire domain configuration for a domain, an '
                     'option group within a domain, or a specific '
                     'configuration option within a group for a domain.'),
        operations=[
            {
                'path': '/v3/domains/{domain_id}/config',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/{domain_id}/config',
                'method': 'HEAD'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}',
                'method': 'HEAD'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}/{option}',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}/{option}',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_get_domain_config,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_security_compliance_domain_config',
        check_str='',
        # This should be accessible to anyone with a valid token, regardless of
        # system-scope or project-scope.
        scope_types=['system', 'domain', 'project'],
        description=('Get security compliance domain configuration for '
                     'either a domain or a specific option in a domain.'),
        operations=[
            {
                'path': '/v3/domains/{domain_id}/config/security_compliance',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/{domain_id}/config/security_compliance',
                'method': 'HEAD'
            },
            {
                'path': ('/v3/domains/{domain_id}/config/'
                         'security_compliance/{option}'),
                'method': 'GET'
            },
            {
                'path': ('/v3/domains/{domain_id}/config/'
                         'security_compliance/{option}'),
                'method': 'HEAD'
            }
        ],
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_domain_config',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=('Update domain configuration for either a domain, '
                     'specific group or a specific option in a group.'),
        operations=[
            {
                'path': '/v3/domains/{domain_id}/config',
                'method': 'PATCH'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}',
                'method': 'PATCH'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}/{option}',
                'method': 'PATCH'
            }
        ],
        deprecated_rule=deprecated_update_domain_config,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_domain_config',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description=('Delete domain configuration for either a domain, '
                     'specific group or a specific option in a group.'),
        operations=[
            {
                'path': '/v3/domains/{domain_id}/config',
                'method': 'DELETE'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}',
                'method': 'DELETE'
            },
            {
                'path': '/v3/domains/{domain_id}/config/{group}/{option}',
                'method': 'DELETE'
            }
        ],
        deprecated_rule=deprecated_delete_domain_config,
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_domain_config_default',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description=('Get domain configuration default for either a domain, '
                     'specific group or a specific option in a group.'),
        operations=[
            {
                'path': '/v3/domains/config/default',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/config/default',
                'method': 'HEAD'
            },
            {
                'path': '/v3/domains/config/{group}/default',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/config/{group}/default',
                'method': 'HEAD'
            },
            {
                'path': '/v3/domains/config/{group}/{option}/default',
                'method': 'GET'
            },
            {
                'path': '/v3/domains/config/{group}/{option}/default',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_get_domain_config_default,
    )
]


def list_rules():
    return domain_config_policies

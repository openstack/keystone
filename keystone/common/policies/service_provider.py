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
    "The service provider API is now aware of system scope and default roles."
)

deprecated_get_sp = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_service_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_list_sp = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_service_providers',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_update_sp = policy.DeprecatedRule(
    name=base.IDENTITY % 'update_service_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_create_sp = policy.DeprecatedRule(
    name=base.IDENTITY % 'create_service_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)
deprecated_delete_sp = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_service_provider',
    check_str=base.RULE_ADMIN_REQUIRED,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.STEIN
)


service_provider_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_service_provider',
        check_str=base.SYSTEM_ADMIN,
        # FIXME(lbragstad): Today, keystone doesn't support federation without
        # modifying configuration files. It makes sense to require system scope
        # for these operations until keystone supports a way to add federated
        # identity and service providers strictly over the API. At that point,
        # it will make sense to include `project` in the list of `scope_types`
        # for service provider policies.
        scope_types=['system'],
        description='Create federated service provider.',
        operations=[{'path': ('/v3/OS-FEDERATION/service_providers/'
                              '{service_provider_id}'),
                     'method': 'PUT'}],
        deprecated_rule=deprecated_create_sp),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_service_providers',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='List federated service providers.',
        operations=[
            {
                'path': '/v3/OS-FEDERATION/service_providers',
                'method': 'GET'
            },
            {
                'path': '/v3/OS-FEDERATION/service_providers',
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_list_sp
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_service_provider',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description='Get federated service provider.',
        operations=[
            {
                'path': ('/v3/OS-FEDERATION/service_providers/'
                         '{service_provider_id}'),
                'method': 'GET'
            },
            {
                'path': ('/v3/OS-FEDERATION/service_providers/'
                         '{service_provider_id}'),
                'method': 'HEAD'
            }
        ],
        deprecated_rule=deprecated_get_sp
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_service_provider',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Update federated service provider.',
        operations=[{'path': ('/v3/OS-FEDERATION/service_providers/'
                              '{service_provider_id}'),
                     'method': 'PATCH'}],
        deprecated_rule=deprecated_update_sp),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_service_provider',
        check_str=base.SYSTEM_ADMIN,
        scope_types=['system'],
        description='Delete federated service provider.',
        operations=[{'path': ('/v3/OS-FEDERATION/service_providers/'
                              '{service_provider_id}'),
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_sp)
]


def list_rules():
    return service_provider_policies

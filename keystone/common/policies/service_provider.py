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

service_provider_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_service_provider',
        check_str=base.RULE_ADMIN_REQUIRED,
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
                     'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_service_providers',
        check_str=base.RULE_ADMIN_REQUIRED,
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
        ]
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_service_provider',
        check_str=base.RULE_ADMIN_REQUIRED,
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
        ]
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_service_provider',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Update federated service provider.',
        operations=[{'path': ('/v3/OS-FEDERATION/service_providers/'
                              '{service_provider_id}'),
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_service_provider',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete federated service provider.',
        operations=[{'path': ('/v3/OS-FEDERATION/service_providers/'
                              '{service_provider_id}'),
                     'method': 'DELETE'}])
]


def list_rules():
    return service_provider_policies

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

collection_path = '/v3/users/{user_id}/application_credentials'
resource_path = collection_path + '/{application_credential_id}'

DEPRECATED_REASON = (
    "The application credential API is now aware of system scope and default "
    "roles."
)

deprecated_list_application_credentials_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'list_application_credentials',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_get_application_credentials_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'get_application_credential',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)
deprecated_delete_application_credentials_for_user = policy.DeprecatedRule(
    name=base.IDENTITY % 'delete_application_credential',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.TRAIN
)


application_credential_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_application_credential',
        check_str=base.RULE_SYSTEM_READER_OR_OWNER,
        scope_types=['system', 'project'],
        description='Show application credential details.',
        operations=[{'path': resource_path,
                     'method': 'GET'},
                    {'path': resource_path,
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_get_application_credentials_for_user),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_application_credentials',
        check_str=base.RULE_SYSTEM_READER_OR_OWNER,
        scope_types=['system', 'project'],
        description='List application credentials for a user.',
        operations=[{'path': collection_path,
                     'method': 'GET'},
                    {'path': collection_path,
                     'method': 'HEAD'}],
        deprecated_rule=deprecated_list_application_credentials_for_user),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_application_credential',
        check_str=base.RULE_OWNER,
        scope_types=['project'],
        description='Create an application credential.',
        operations=[{'path': collection_path,
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_application_credential',
        check_str=base.RULE_SYSTEM_ADMIN_OR_OWNER,
        scope_types=['system', 'project'],
        description='Delete an application credential.',
        operations=[{'path': resource_path,
                     'method': 'DELETE'}],
        deprecated_rule=deprecated_delete_application_credentials_for_user)
]


def list_rules():
    return application_credential_policies

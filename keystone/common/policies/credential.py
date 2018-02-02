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

credential_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad): Credentials aren't really project-scoped or
        # system-scoped. Instead, they are tied to a user. If this API is
        # called with a system-scoped token, it's a system-administrator and
        # they should be able to get any credential for management reasons. If
        # this API is called with a project-scoped token, then extra
        # enforcement needs to happen based on who created the credential, what
        # projects they are members of, and the project the token is scoped to.
        # When we fully support the second case, we can add `project` to the
        # list of scope_types. This comment applies to the rest of the policies
        # in this module.
        # scope_types=['system', 'project'],
        description='Show credentials details.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_credentials',
        check_str=base.RULE_ADMIN_REQUIRED,
        # scope_types=['system', 'project'],
        description='List credentials.',
        operations=[{'path': '/v3/credentials',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        # scope_types=['system', 'project'],
        description='Create credential.',
        operations=[{'path': '/v3/credentials',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'update_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        # scope_types=['system', 'project'],
        description='Update credential.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'PATCH'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_credential',
        check_str=base.RULE_ADMIN_REQUIRED,
        # scope_types=['system', 'project'],
        description='Delete credential.',
        operations=[{'path': '/v3/credentials/{credential_id}',
                     'method': 'DELETE'}])
]


def list_rules():
    return credential_policies

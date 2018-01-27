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
        check_str='',
        scope_types=['project'],
        description='List trusts.',
        operations=[{'path': '/v3/OS-TRUST/trusts',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_roles_for_trust',
        check_str='',
        scope_types=['project'],
        description='List roles delegated by a trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}/roles',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts/{trust_id}/roles',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_role_for_trust',
        check_str='',
        scope_types=['project'],
        description='Check if trust delegates a particular role.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_trust',
        check_str='',
        scope_types=['project'],
        description='Revoke trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}',
                     'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_trust',
        check_str='',
        scope_types=['project'],
        description='Get trust.',
        operations=[{'path': '/v3/OS-TRUST/trusts/{trust_id}',
                     'method': 'GET'},
                    {'path': '/v3/OS-TRUST/trusts/{trust_id}',
                     'method': 'HEAD'}])
]


def list_rules():
    return trust_policies

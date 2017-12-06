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

implied_role_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_implied_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        # FIXME(lbragstad) The management of implied roles currently makes
        # sense as a system-only resource. Once keystone has the ability to
        # support RBAC solely over the API without having to customize policy
        # files, scope_types should include 'project'.
        scope_types=['system'],
        description='Get information about an association between two roles. '
                    'When a relationship exists between a prior role and an '
                    'implied role and the prior role is assigned to a user, '
                    'the user also assumes the implied role.',
        operations=[
            {'path': '/v3/roles/{prior_role_id}/implies/{implied_role_id}',
             'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_implied_roles',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List associations between two roles. When a relationship '
                    'exists between a prior role and an implied role and the '
                    'prior role is assigned to a user, the user also assumes '
                    'the implied role. This will return all the implied roles '
                    'that would be assumed by the user who gets the specified '
                    'prior role.',
        operations=[
            {'path': '/v3/roles/{prior_role_id}/implies', 'method': 'GET'},
            {'path': '/v3/roles/{prior_role_id}/implies', 'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'create_implied_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Create an association between two roles. When a '
                    'relationship exists between a prior role and an implied '
                    'role and the prior role is assigned to a user, the user '
                    'also assumes the implied role.',
        operations=[
            {'path': '/v3/roles/{prior_role_id}/implies/{implied_role_id}',
             'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_implied_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Delete the association between two roles. When a '
                    'relationship exists between a prior role and an implied '
                    'role and the prior role is assigned to a user, the user '
                    'also assumes the implied role. Removing the association '
                    'will cause that effect to be eliminated.',
        operations=[
            {'path': '/v3/roles/{prior_role_id}/implies/{implied_role_id}',
             'method': 'DELETE'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_role_inference_rules',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='List all associations between two roles in the system. '
                    'When a relationship exists between a prior role and an '
                    'implied role and the prior role is assigned to a user, '
                    'the user also assumes the implied role.',
        operations=[
            {'path': '/v3/role_inferences', 'method': 'GET'},
            {'path': '/v3/role_inferences', 'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_implied_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['system'],
        description='Check an association between two roles. When a '
                    'relationship exists between a prior role and an implied '
                    'role and the prior role is assigned to a user, the user '
                    'also assumes the implied role.',
        operations=[
            {'path': '/v3/roles/{prior_role_id}/implies/{implied_role_id}',
             'method': 'HEAD'}])
]


def list_rules():
    return implied_role_policies

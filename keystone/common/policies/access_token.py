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

access_token_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'authorize_request_token',
        check_str=base.RULE_ADMIN_REQUIRED,
        # Since access tokens require a request token and request tokens
        # require a project, it makes sense to have a project-scoped token in
        # order to access these APIs.
        scope_types=['project'],
        description='Authorize OAUTH1 request token.',
        operations=[{'path': '/v3/OS-OAUTH1/authorize/{request_token_id}',
                     'method': 'PUT'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_access_token',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['project'],
        description='Get OAUTH1 access token for user by access token ID.',
        operations=[{'path': ('/v3/users/{user_id}/OS-OAUTH1/access_tokens/'
                              '{access_token_id}'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_access_token_role',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['project'],
        description='Get role for user OAUTH1 access token.',
        operations=[{'path': ('/v3/users/{user_id}/OS-OAUTH1/access_tokens/'
                              '{access_token_id}/roles/{role_id}'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_access_tokens',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['project'],
        description='List OAUTH1 access tokens for user.',
        operations=[{'path': '/v3/users/{user_id}/OS-OAUTH1/access_tokens',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_access_token_roles',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['project'],
        description='List OAUTH1 access token roles.',
        operations=[{'path': ('/v3/users/{user_id}/OS-OAUTH1/access_tokens/'
                              '{access_token_id}/roles'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'delete_access_token',
        check_str=base.RULE_ADMIN_REQUIRED,
        scope_types=['project'],
        description='Delete OAUTH1 access token.',
        operations=[{'path': ('/v3/users/{user_id}/OS-OAUTH1/access_tokens/'
                              '{access_token_id}'),
                     'method': 'DELETE'}])
]


def list_rules():
    return access_token_policies

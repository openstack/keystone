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

token_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'check_token',
        check_str=base.RULE_ADMIN_OR_TOKEN_SUBJECT,
        # FIXME(lbragstad): Token validation should be handled within keystone,
        # but it makes sense to have this be a system-level operation and a
        # project-level operation. If this API is called by a system-level
        # administrator, they should be able to check any token. If this API
        # is called by a project administrator, then the token should be
        # checked with respect to the project the administrator has a role on.
        # Otherwise it would be possible for administrators in one project to
        # validate tokens scoped to another project, which is a security
        # concern. Note the following line should be uncommented once keystone
        # supports the ability for project administrators to validate tokens
        # only within their project.
        # scope_types=['system', 'project'],
        description='Check a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'HEAD'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'validate_token',
        check_str=base.RULE_SERVICE_ADMIN_OR_TOKEN_SUBJECT,
        # FIXME(lbragstad): See the comment above about why this is commented
        # out. If this weren't commented out and the `enforce_scope` were set
        # to True, then users with project-scoped tokens would no longer be
        # able to validate them by setting the same token as the X-Auth-Header
        # and X-Subject-Token.
        # scope_types=['system', 'project'],
        description='Validate a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revoke_token',
        check_str=base.RULE_ADMIN_OR_TOKEN_SUBJECT,
        # FIXME(lbragstad): System administrators should be able to revoke any
        # valid token. Project administrators should only be able to invalidate
        # tokens scoped to the project they administer. Users should be able to
        # invalidate their own tokens. If we uncommented this line without
        # adding support for each of these cases in code, we'd be breaking the
        # ability for users to invalidate their own tokens.
        # scope_types=['system', 'project'],
        description='Revoke a token.',
        operations=[{'path': '/v3/auth/tokens',
                     'method': 'DELETE'}])
]


def list_rules():
    return token_policies

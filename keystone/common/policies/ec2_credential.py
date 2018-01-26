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

ec2_credential_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_get_credential',
        check_str=base.RULE_ADMIN_OR_CREDENTIAL_OWNER,
        # FIXME(lbragstad): System administrator should be able to manage all
        # ec2 credentials. Users with a system role assignment should be able
        # to manage only ec2 credentials keystone can assert belongs to them.
        # This is going to require keystone to have "scope" checks in code to
        # ensure this is enforced properly. Until keystone has support for
        # those cases in code, we're going to have to comment this out. This
        # would be a good candidate for a user-scoped operation. If we provide
        # scope_types in these policies without proper scope checks in code we
        # could expose credentials to users who are not supposed to access
        # them.
        # scope_types=['system', 'project'],
        description='Show ec2 credential details.',
        operations=[{'path': ('/v3/users/{user_id}/credentials/OS-EC2/'
                              '{credential_id}'),
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_list_credentials',
        check_str=base.RULE_ADMIN_OR_OWNER,
        # FIXME(lbragstad): See the above comment as to why scope_types is
        # commented out.
        # scope_types=['system', 'project'],
        description='List ec2 credentials.',
        operations=[{'path': '/v3/users/{user_id}/credentials/OS-EC2',
                     'method': 'GET'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_create_credential',
        check_str=base.RULE_ADMIN_OR_OWNER,
        # FIXME(lbragstad): See the above comment as to why scope_types is
        # commented out.
        description='Create ec2 credential.',
        operations=[{'path': '/v3/users/{user_id}/credentials/OS-EC2',
                     'method': 'POST'}]),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'ec2_delete_credential',
        check_str=base.RULE_ADMIN_OR_CREDENTIAL_OWNER,
        # FIXME(lbragstad): See the above comment as to why scope_types is
        # commented out.
        # scope_types=['system', 'project'],
        description='Delete ec2 credential.',
        operations=[{'path': ('/v3/users/{user_id}/credentials/OS-EC2/'
                              '{credential_id}'),
                     'method': 'DELETE'}])
]


def list_rules():
    return ec2_credential_policies

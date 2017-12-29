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

auth_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_auth_catalog',
        check_str='',
        description='Get service catalog.',
        operations=[
            {
                'path': '/v3/auth/catalog',
                'method': 'GET'
            },
            {
                'path': '/v3/auth/catalog',
                'method': 'HEAD'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_auth_projects',
        check_str='',
        description=('List all projects a user has access to via role '
                     'assignments.'),
        operations=[
            {
                'path': '/v3/auth/projects',
                'method': 'GET'
            },
            {
                'path': '/v3/auth/projects',
                'method': 'HEAD'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_auth_domains',
        check_str='',
        description=('List all domains a user has access to via role '
                     'assignments.'),
        operations=[
            {
                'path': '/v3/auth/domains',
                'method': 'GET'
            },
            {
                'path': '/v3/auth/domains',
                'method': 'HEAD'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'get_auth_system',
        check_str='',
        description='List systems a user has access to via role assignments.',
        operations=[
            {
                'path': '/v3/auth/system',
                'method': 'GET'
            },
            {
                'path': '/v3/auth/system',
                'method': 'HEAD'
            }
        ]
    )
]


def list_rules():
    return auth_policies

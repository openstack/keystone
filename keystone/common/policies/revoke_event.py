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

revoke_event_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'list_revoke_events',
        check_str=base.RULE_SERVICE_OR_ADMIN,
        # NOTE(lbragstad): This API was originally introduced so that services
        # could invalidate tokens based on revocation events. This is system
        # specific so it make sense to associate `system` as the scope type
        # required for this policy.
        scope_types=['system'],
        description='List revocation events.',
        operations=[{'path': '/v3/OS-REVOKE/events',
                     'method': 'GET'}])
]


def list_rules():
    return revoke_event_policies

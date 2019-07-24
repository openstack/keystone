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

DEPRECATED_REASON = """
The identity:revocation_list policy isn't used to protect any APIs in keystone
now that the revocation list API has been deprecated and only returns a 410 or
403 depending on how keystone is configured. This policy can be safely removed
from policy files.
"""

token_revocation_policies = [
    policy.DocumentedRuleDefault(
        name=base.IDENTITY % 'revocation_list',
        check_str=base.RULE_SERVICE_OR_ADMIN,
        # NOTE(lbragstad): Documenting scope_types here doesn't really make a
        # difference since this API is going to return an empty list regardless
        # of the token scope used in the API call. More-or-less just doing this
        # for consistency with other policies.
        scope_types=['system', 'project'],
        description='List revoked PKI tokens.',
        operations=[{'path': '/v3/auth/tokens/OS-PKI/revoked',
                     'method': 'GET'}],
        deprecated_for_removal=True,
        deprecated_since=versionutils.deprecated.TRAIN,
        deprecated_reason=DEPRECATED_REASON
    )
]


def list_rules():
    return token_revocation_policies

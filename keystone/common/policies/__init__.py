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

import itertools

from keystone.common.policies import access_rule
from keystone.common.policies import access_token
from keystone.common.policies import application_credential
from keystone.common.policies import auth
from keystone.common.policies import base
from keystone.common.policies import consumer
from keystone.common.policies import credential
from keystone.common.policies import domain
from keystone.common.policies import domain_config
from keystone.common.policies import ec2_credential
from keystone.common.policies import endpoint
from keystone.common.policies import endpoint_group
from keystone.common.policies import grant
from keystone.common.policies import group
from keystone.common.policies import identity_provider
from keystone.common.policies import implied_role
from keystone.common.policies import limit
from keystone.common.policies import mapping
from keystone.common.policies import policy
from keystone.common.policies import policy_association
from keystone.common.policies import project
from keystone.common.policies import project_endpoint
from keystone.common.policies import protocol
from keystone.common.policies import region
from keystone.common.policies import registered_limit
from keystone.common.policies import revoke_event
from keystone.common.policies import role
from keystone.common.policies import role_assignment
from keystone.common.policies import service
from keystone.common.policies import service_provider
from keystone.common.policies import token
from keystone.common.policies import token_revocation
from keystone.common.policies import trust
from keystone.common.policies import user


def list_rules():
    return itertools.chain(
        base.list_rules(),
        access_rule.list_rules(),
        access_token.list_rules(),
        application_credential.list_rules(),
        auth.list_rules(),
        consumer.list_rules(),
        credential.list_rules(),
        domain.list_rules(),
        domain_config.list_rules(),
        ec2_credential.list_rules(),
        endpoint.list_rules(),
        endpoint_group.list_rules(),
        grant.list_rules(),
        group.list_rules(),
        identity_provider.list_rules(),
        implied_role.list_rules(),
        limit.list_rules(),
        mapping.list_rules(),
        policy.list_rules(),
        policy_association.list_rules(),
        project.list_rules(),
        project_endpoint.list_rules(),
        protocol.list_rules(),
        region.list_rules(),
        registered_limit.list_rules(),
        revoke_event.list_rules(),
        role.list_rules(),
        role_assignment.list_rules(),
        service.list_rules(),
        service_provider.list_rules(),
        token_revocation.list_rules(),
        token.list_rules(),
        trust.list_rules(),
        user.list_rules(),
    )

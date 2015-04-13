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

from keystone import assignment
from keystone import auth
from keystone import catalog
from keystone.common import cache
from keystone.contrib import endpoint_filter
from keystone.contrib import federation
from keystone.contrib import oauth1
from keystone.contrib import revoke
from keystone import credential
from keystone import endpoint_policy
from keystone import identity
from keystone import policy
from keystone import resource
from keystone import token
from keystone import trust


def load_backends():

    # Configure and build the cache
    cache.configure_cache_region(cache.REGION)

    # Ensure that the identity driver is created before the assignment manager
    # and that the assignment driver is created before the resource manager.
    # The default resource driver depends on assignment, which in turn
    # depends on identity - hence we need to ensure the chain is available.
    _IDENTITY_API = identity.Manager()
    _ASSIGNMENT_API = assignment.Manager()

    DRIVERS = dict(
        assignment_api=_ASSIGNMENT_API,
        catalog_api=catalog.Manager(),
        credential_api=credential.Manager(),
        domain_config_api=resource.DomainConfigManager(),
        endpoint_filter_api=endpoint_filter.Manager(),
        endpoint_policy_api=endpoint_policy.Manager(),
        federation_api=federation.Manager(),
        id_generator_api=identity.generator.Manager(),
        id_mapping_api=identity.MappingManager(),
        identity_api=_IDENTITY_API,
        oauth_api=oauth1.Manager(),
        policy_api=policy.Manager(),
        resource_api=resource.Manager(),
        revoke_api=revoke.Manager(),
        role_api=assignment.RoleManager(),
        token_api=token.persistence.Manager(),
        trust_api=trust.Manager(),
        token_provider_api=token.provider.Manager())

    auth.controllers.load_auth_methods()

    return DRIVERS

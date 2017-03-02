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
from keystone import credential
from keystone import endpoint_policy
from keystone import federation
from keystone import identity
from keystone import oauth1
from keystone import policy
from keystone import resource
from keystone import revoke
from keystone import token
from keystone import trust


def load_backends():

    # Configure and build the cache
    cache.configure_cache()
    cache.configure_cache(region=catalog.COMPUTED_CATALOG_REGION)
    cache.configure_cache(region=assignment.COMPUTED_ASSIGNMENTS_REGION)
    cache.configure_cache(region=revoke.REVOKE_REGION)
    cache.configure_cache(region=token.provider.TOKENS_REGION)
    cache.configure_cache(region=identity.ID_MAPPING_REGION)
    cache.configure_invalidation_region()

    # NOTE(knikolla): The assignment manager must be instantiated before the
    # resource manager. The current dictionary ordering ensures that.
    DRIVERS = dict(
        assignment_api=assignment.Manager(),
        catalog_api=catalog.Manager(),
        credential_api=credential.Manager(),
        credential_provider_api=credential.provider.Manager(),
        domain_config_api=resource.DomainConfigManager(),
        endpoint_policy_api=endpoint_policy.Manager(),
        federation_api=federation.Manager(),
        id_generator_api=identity.generator.Manager(),
        id_mapping_api=identity.MappingManager(),
        identity_api=identity.Manager(),
        shadow_users_api=identity.ShadowUsersManager(),
        oauth_api=oauth1.Manager(),
        policy_api=policy.Manager(),
        resource_api=resource.Manager(),
        revoke_api=revoke.Manager(),
        role_api=assignment.RoleManager(),
        token_api=token.persistence.Manager(),
        trust_api=trust.Manager(),
        token_provider_api=token.provider.Manager())

    auth.core.load_auth_methods()

    return DRIVERS

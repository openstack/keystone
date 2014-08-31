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
from keystone.contrib import endpoint_policy
from keystone import credential
from keystone import identity
from keystone import policy
from keystone import token
from keystone import trust


def load_backends():

    # Configure and build the cache
    cache.configure_cache_region(cache.REGION)

    # Ensure that the identity driver is created before the assignment manager.
    # The default assignment driver is determined by the identity driver, so
    # the identity driver must be available to the assignment manager.
    _IDENTITY_API = identity.Manager()

    DRIVERS = dict(
        assignment_api=assignment.Manager(),
        catalog_api=catalog.Manager(),
        credential_api=credential.Manager(),
        endpoint_filter_api=endpoint_filter.Manager(),
        endpoint_policy_api=endpoint_policy.Manager(),
        id_generator_api=identity.generator.Manager(),
        id_mapping_api=identity.MappingManager(),
        identity_api=_IDENTITY_API,
        policy_api=policy.Manager(),
        token_api=token.persistence.Manager(),
        trust_api=trust.Manager(),
        token_provider_api=token.provider.Manager())

    auth.controllers.load_auth_methods()

    return DRIVERS

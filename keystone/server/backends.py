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
import sys

from oslo_log import log

from keystone import application_credential
from keystone import assignment
from keystone import auth
from keystone import catalog
from keystone.common import cache
from keystone.common import provider_api
from keystone import credential
from keystone import endpoint_policy
from keystone import exception
from keystone import federation
from keystone import identity
from keystone import limit
from keystone import oauth1
from keystone import policy
from keystone import receipt
from keystone import resource
from keystone import revoke
from keystone import token
from keystone import trust

LOG = log.getLogger(__name__)


def load_backends():

    # Configure and build the cache
    cache.configure_cache()
    cache.configure_cache(region=catalog.COMPUTED_CATALOG_REGION)
    cache.configure_cache(region=assignment.COMPUTED_ASSIGNMENTS_REGION)
    cache.configure_cache(region=revoke.REVOKE_REGION)
    cache.configure_cache(region=token.provider.TOKENS_REGION)
    cache.configure_cache(region=receipt.provider.RECEIPTS_REGION)
    cache.configure_cache(region=identity.ID_MAPPING_REGION)
    cache.configure_invalidation_region()

    managers = [application_credential.Manager, assignment.Manager,
                catalog.Manager, credential.Manager,
                credential.provider.Manager, resource.DomainConfigManager,
                endpoint_policy.Manager, federation.Manager,
                identity.generator.Manager, identity.MappingManager,
                identity.Manager, identity.ShadowUsersManager,
                limit.Manager, oauth1.Manager, policy.Manager,
                resource.Manager, revoke.Manager, assignment.RoleManager,
                receipt.provider.Manager, trust.Manager,
                token.provider.Manager]

    drivers = {d._provides_api: d() for d in managers}

    # NOTE(morgan): lock the APIs, these should only ever be instantiated
    # before running keystone.
    provider_api.ProviderAPIs.lock_provider_registry()
    try:
        # Check project depth before start process. If fail, Keystone will not
        # start.
        drivers['unified_limit_api'].check_project_depth()
    except exception.LimitTreeExceedError as e:
        LOG.critical(e)
        sys.exit(1)

    auth.core.load_auth_methods()

    return drivers

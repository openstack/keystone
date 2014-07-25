# Copyright 2012 OpenStack Foundation
#
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

"""Main entry point into the Token service."""

from keystone.common import cache
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone.openstack.common import log
from keystone.openstack.common import versionutils
from keystone.token import persistence
from keystone.token import provider


CONF = config.CONF
LOG = log.getLogger(__name__)
SHOULD_CACHE = cache.should_cache_fn('token')

# NOTE(blk-u): The config options are not available at import time.
EXPIRATION_TIME = lambda: CONF.token.cache_time
REVOCATION_CACHE_EXPIRATION_TIME = lambda: CONF.token.revocation_cache_time


@versionutils.deprecated(
    as_of=versionutils.deprecated.JUNO,
    in_favor_of='keystone.token.provider.default_expire_time',
    what='keystone.token.default_expire_time',
    remove_in=+1)
def default_expire_time():
    return provider.default_expire_time()


@versionutils.deprecated(as_of=versionutils.deprecated.JUNO,
                         what='keystone.token.core.validate_auth_info',
                         remove_in=+1)
def validate_auth_info(self, user_ref, tenant_ref):
    """Validate user and tenant auth info.

    Validate the user and tenant auth info in order to ensure that user and
    tenant information is valid and not disabled.

    Consolidate the checks here to ensure consistency between token auth and
    ec2 auth.

    :params user_ref: the authenticating user
    :params tenant_ref: the scope of authorization, if any
    :raises Unauthorized: if any of the user, user's domain, tenant or
            tenant's domain are either disabled or otherwise invalid
    """
    # If the user is disabled don't allow them to authenticate
    if not user_ref.get('enabled', True):
        msg = _('User is disabled: %s') % user_ref['id']
        LOG.warning(msg)
        raise exception.Unauthorized(msg)

    # If the user's domain is disabled don't allow them to authenticate
    user_domain_ref = self.assignment_api.get_domain(
        user_ref['domain_id'])
    if user_domain_ref and not user_domain_ref.get('enabled', True):
        msg = _('Domain is disabled: %s') % user_domain_ref['id']
        LOG.warning(msg)
        raise exception.Unauthorized(msg)

    if tenant_ref:
        # If the project is disabled don't allow them to authenticate
        if not tenant_ref.get('enabled', True):
            msg = _('Tenant is disabled: %s') % tenant_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

        # If the project's domain is disabled don't allow them to authenticate
        project_domain_ref = self.assignment_api.get_domain(
            tenant_ref['domain_id'])
        if (project_domain_ref and
                not project_domain_ref.get('enabled', True)):
            msg = _('Domain is disabled: %s') % project_domain_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)


class Manager(persistence.Manager):
    @versionutils.deprecated(
        versionutils.deprecated.JUNO,
        in_favor_of='keystone.token.persistence.Manager',
        remove_in=+1,
        what='keystone.token.core.Manager')
    def __init__(self):
        super(Manager, self).__init__()


class Driver(persistence.Driver):
    @versionutils.deprecated(
        versionutils.deprecated.JUNO,
        in_favor_of='keystone.token.persistence.Driver',
        remove_in=+1,
        what='keystone.token.core.Driver')
    def __init__(self):
        super(Driver, self).__init__()

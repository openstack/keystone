# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import datetime

from keystone.common import cms
from keystone.common import dependency
from keystone.common import logging
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.openstack.common import timeutils


CONF = config.CONF
config.register_int('expiration', group='token', default=86400)
LOG = logging.getLogger(__name__)


def unique_id(token_id):
    """Return a unique ID for a token.

    The returned value is useful as the primary key of a database table,
    memcache store, or other lookup table.

    :returns: Given a PKI token, returns it's hashed value. Otherwise, returns
              the passed-in value (such as a UUID token ID or an existing
              hash).
    """
    return cms.cms_hash_token(token_id)


def default_expire_time():
    """Determine when a fresh token should expire.

    Expiration time varies based on configuration (see ``[token] expiration``).

    :returns: a naive UTC datetime.datetime object

    """
    expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
    return timeutils.utcnow() + expire_delta


def validate_auth_info(self, context, user_ref, tenant_ref):
    """Validate user and tenant auth info.

    Validate the user and tenant auth into in order to ensure that user and
    tenant information is valid and not disabled.

    Consolidate the checks here to ensure consistency between token auth and
    ec2 auth.

    :params context: keystone's request context
    :params user_ref: the authenticating user
    :params tenant_ref: the scope of authorization, if any
    :raises Unauthorized: if any of the user, user's domain, tenant or
            tenant's domain are either disabled or otherwise invalid
    """
    # If the user is disabled don't allow them to authenticate
    if not user_ref.get('enabled', True):
        msg = 'User is disabled: %s' % user_ref['id']
        LOG.warning(msg)
        raise exception.Unauthorized(msg)

    # If the user's domain is disabled don't allow them to authenticate
    user_domain_ref = self.identity_api.get_domain(
        context,
        user_ref['domain_id'])
    if user_domain_ref and not user_domain_ref.get('enabled', True):
        msg = 'Domain is disabled: %s' % user_domain_ref['id']
        LOG.warning(msg)
        raise exception.Unauthorized(msg)

    if tenant_ref:
        # If the project is disabled don't allow them to authenticate
        if not tenant_ref.get('enabled', True):
            msg = 'Tenant is disabled: %s' % tenant_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)

        # If the project's domain is disabled don't allow them to authenticate
        project_domain_ref = self.identity_api.get_domain(
            context,
            tenant_ref['domain_id'])
        if (project_domain_ref and
                not project_domain_ref.get('enabled', True)):
            msg = 'Domain is disabled: %s' % project_domain_ref['id']
            LOG.warning(msg)
            raise exception.Unauthorized(msg)


@dependency.provider('token_api')
class Manager(manager.Manager):
    """Default pivot point for the Token backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.token.driver)


class Driver(object):
    """Interface description for a Token driver."""

    def get_token(self, token_id):
        """Get a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: token_ref
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()

    def create_token(self, token_id, data):
        """Create a token by id and data.

        :param token_id: identity of the token
        :type token_id: string
        :param data: dictionary with additional reference information

        ::

            {
                expires=''
                id=token_id,
                user=user_ref,
                tenant=tenant_ref,
                metadata=metadata_ref
            }

        :type data: dict
        :returns: token_ref or None.

        """
        raise exception.NotImplemented()

    def delete_token(self, token_id):
        """Deletes a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: None.
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()

    def list_tokens(self, user_id, tenant_id=None, trust_id=None):
        """Returns a list of current token_id's for a user

        :param user_id: identity of the user
        :type user_id: string
        :param tenant_id: identity of the tenant
        :type tenant_id: string
        :param trust_id: identified of the trust
        :type trust_id: string
        :returns: list of token_id's

        """
        raise exception.NotImplemented()

    def list_revoked_tokens(self):
        """Returns a list of all revoked tokens

        :returns: list of token_id's

        """
        raise exception.NotImplemented()

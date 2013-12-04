# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import abc
import copy
import datetime

import six

from keystone.common import cache
from keystone.common import cms
from keystone.common import dependency
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils


CONF = config.CONF
LOG = logging.getLogger(__name__)
SHOULD_CACHE = cache.should_cache_fn('token')


def default_expire_time():
    """Determine when a fresh token should expire.

    Expiration time varies based on configuration (see ``[token] expiration``).

    :returns: a naive UTC datetime.datetime object

    """
    expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
    return timeutils.utcnow() + expire_delta


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


@dependency.requires('token_provider_api')
@dependency.provider('token_api')
class Manager(manager.Manager):
    """Default pivot point for the Token backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.token.driver)

    def unique_id(self, token_id):
        """Return a unique ID for a token.

        The returned value is useful as the primary key of a database table,
        memcache store, or other lookup table.

        :returns: Given a PKI token, returns it's hashed value. Otherwise,
                  returns the passed-in value (such as a UUID token ID or an
                  existing hash).
        """
        return cms.cms_hash_token(token_id)

    def _assert_valid(self, token_id, token_ref):
        """Raise TokenNotFound if the token is expired."""
        current_time = timeutils.normalize_time(timeutils.utcnow())
        expires = token_ref.get('expires')
        if not expires or current_time > timeutils.normalize_time(expires):
            raise exception.TokenNotFound(token_id=token_id)

    def get_token(self, token_id):
        unique_id = self.unique_id(token_id)
        token_ref = self._get_token(unique_id)
        # NOTE(morganfainberg): Lift expired checking to the manager, there is
        # no reason to make the drivers implement this check. With caching,
        # self._get_token could return an expired token. Make sure we behave
        # as expected and raise TokenNotFound on those instances.
        self._assert_valid(token_id, token_ref)
        return token_ref

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.token.cache_time)
    def _get_token(self, token_id):
        # Only ever use the "unique" id in the cache key.
        return self.driver.get_token(token_id)

    def create_token(self, token_id, data):
        unique_id = self.unique_id(token_id)
        data_copy = copy.deepcopy(data)
        data_copy['id'] = unique_id
        ret = self.driver.create_token(unique_id, data_copy)
        if SHOULD_CACHE(ret):
            # NOTE(morganfainberg): when doing a cache set, you must pass the
            # same arguments through, the same as invalidate (this includes
            # "self"). First argument is always the value to be cached
            self._get_token.set(ret, self, unique_id)
        return ret

    def delete_token(self, token_id):
        unique_id = self.unique_id(token_id)
        self.driver.delete_token(unique_id)
        self._invalidate_individual_token_cache(unique_id)
        self.invalidate_revocation_list()

    def delete_tokens(self, user_id, tenant_id=None, trust_id=None,
                      consumer_id=None):
        token_list = self.driver.list_tokens(user_id, tenant_id, trust_id,
                                             consumer_id)
        self.driver.delete_tokens(user_id, tenant_id, trust_id, consumer_id)
        for token_id in token_list:
            unique_id = self.unique_id(token_id)
            self._invalidate_individual_token_cache(unique_id)
        self.invalidate_revocation_list()

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=CONF.token.revocation_cache_time)
    def list_revoked_tokens(self):
        return self.driver.list_revoked_tokens()

    def invalidate_revocation_list(self):
        # NOTE(morganfainberg): Note that ``self`` needs to be passed to
        # invalidate() because of the way the invalidation method works on
        # determining cache-keys.
        self.list_revoked_tokens.invalidate(self)

    def _invalidate_individual_token_cache(self, token_id):
        # NOTE(morganfainberg): invalidate takes the exact same arguments as
        # the normal method, this means we need to pass "self" in (which gets
        # stripped off).

        # FIXME(morganfainberg): Does this cache actually need to be
        # invalidated? We maintain a cached revocation list, which should be
        # consulted before accepting a token as valid.  For now we will
        # do the explicit individual token invalidation.
        self._get_token.invalidate(self, token_id)
        self.token_provider_api.invalidate_individual_token_cache(token_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for a Token driver."""

    @abc.abstractmethod
    def get_token(self, token_id):
        """Get a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: token_ref
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
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

    @abc.abstractmethod
    def delete_token(self, token_id):
        """Deletes a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: None.
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_tokens(self, user_id, tenant_id=None, trust_id=None,
                      consumer_id=None):
        """Deletes tokens by user.

        If the tenant_id is not None, only delete the tokens by user id under
        the specified tenant.

        If the trust_id is not None, it will be used to query tokens and the
        user_id will be ignored.

        If the consumer_id is not None, only delete the tokens by consumer id
        that match the specified consumer id.

        :param user_id: identity of user
        :type user_id: string
        :param tenant_id: identity of the tenant
        :type tenant_id: string
        :param trust_id: identity of the trust
        :type trust_id: string
        :param consumer_id: identity of the consumer
        :type consumer_id: string
        :returns: None.
        :raises: keystone.exception.TokenNotFound

        """
        token_list = self.list_tokens(user_id,
                                      tenant_id=tenant_id,
                                      trust_id=trust_id,
                                      consumer_id=consumer_id)

        for token in token_list:
            try:
                self.delete_token(token)
            except exception.NotFound:
                pass

    @abc.abstractmethod
    def list_tokens(self, user_id, tenant_id=None, trust_id=None,
                    consumer_id=None):
        """Returns a list of current token_id's for a user

        This is effectively a private method only used by the ``delete_tokens``
        method and should not be called by anything outside of the
        ``token_api`` manager or the token driver itself.

        :param user_id: identity of the user
        :type user_id: string
        :param tenant_id: identity of the tenant
        :type tenant_id: string
        :param trust_id: identity of the trust
        :type trust_id: string
        :param consumer_id: identity of the consumer
        :type consumer_id: string
        :returns: list of token_id's

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_revoked_tokens(self):
        """Returns a list of all revoked tokens

        :returns: list of token_id's

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def flush_expired_tokens(self):
        """Archive or delete tokens that have expired.
        """
        raise exception.NotImplemented()

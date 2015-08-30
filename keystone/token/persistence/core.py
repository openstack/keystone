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

"""Main entry point into the Token Persistence service."""

import abc
import copy

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
import six

from keystone.common import cache
from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone.i18n import _LW
from keystone.token import utils


CONF = cfg.CONF
LOG = log.getLogger(__name__)
MEMOIZE = cache.get_memoization_decorator(section='token')
REVOCATION_MEMOIZE = cache.get_memoization_decorator(
    section='token', expiration_section='revoke')


@dependency.requires('assignment_api', 'identity_api', 'resource_api',
                     'token_provider_api', 'trust_api')
class PersistenceManager(manager.Manager):
    """Default pivot point for the Token Persistence backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.token.persistence'

    def __init__(self):
        super(PersistenceManager, self).__init__(CONF.token.driver)

    def _assert_valid(self, token_id, token_ref):
        """Raise TokenNotFound if the token is expired."""
        current_time = timeutils.normalize_time(timeutils.utcnow())
        expires = token_ref.get('expires')
        if not expires or current_time > timeutils.normalize_time(expires):
            raise exception.TokenNotFound(token_id=token_id)

    def get_token(self, token_id):
        if not token_id:
            # NOTE(morganfainberg): There are cases when the
            # context['token_id'] will in-fact be None. This also saves
            # a round-trip to the backend if we don't have a token_id.
            raise exception.TokenNotFound(token_id='')
        unique_id = utils.generate_unique_id(token_id)
        token_ref = self._get_token(unique_id)
        # NOTE(morganfainberg): Lift expired checking to the manager, there is
        # no reason to make the drivers implement this check. With caching,
        # self._get_token could return an expired token. Make sure we behave
        # as expected and raise TokenNotFound on those instances.
        self._assert_valid(token_id, token_ref)
        return token_ref

    @MEMOIZE
    def _get_token(self, token_id):
        # Only ever use the "unique" id in the cache key.
        return self.driver.get_token(token_id)

    def create_token(self, token_id, data):
        unique_id = utils.generate_unique_id(token_id)
        data_copy = copy.deepcopy(data)
        data_copy['id'] = unique_id
        ret = self.driver.create_token(unique_id, data_copy)
        if MEMOIZE.should_cache(ret):
            # NOTE(morganfainberg): when doing a cache set, you must pass the
            # same arguments through, the same as invalidate (this includes
            # "self"). First argument is always the value to be cached
            self._get_token.set(ret, self, unique_id)
        return ret

    def delete_token(self, token_id):
        if not CONF.token.revoke_by_id:
            return
        unique_id = utils.generate_unique_id(token_id)
        self.driver.delete_token(unique_id)
        self._invalidate_individual_token_cache(unique_id)
        self.invalidate_revocation_list()

    def delete_tokens(self, user_id, tenant_id=None, trust_id=None,
                      consumer_id=None):
        if not CONF.token.revoke_by_id:
            return
        token_list = self.driver.delete_tokens(user_id, tenant_id, trust_id,
                                               consumer_id)
        for token_id in token_list:
            unique_id = utils.generate_unique_id(token_id)
            self._invalidate_individual_token_cache(unique_id)
        self.invalidate_revocation_list()

    @REVOCATION_MEMOIZE
    def list_revoked_tokens(self):
        return self.driver.list_revoked_tokens()

    def invalidate_revocation_list(self):
        # NOTE(morganfainberg): Note that ``self`` needs to be passed to
        # invalidate() because of the way the invalidation method works on
        # determining cache-keys.
        self.list_revoked_tokens.invalidate(self)

    def delete_tokens_for_domain(self, domain_id):
        """Delete all tokens for a given domain.

        It will delete all the project-scoped tokens for the projects
        that are owned by the given domain, as well as any tokens issued
        to users that are owned by this domain.

        However, deletion of domain_scoped tokens will still need to be
        implemented as stated in TODO below.
        """
        if not CONF.token.revoke_by_id:
            return
        projects = self.resource_api.list_projects()
        for project in projects:
            if project['domain_id'] == domain_id:
                for user_id in self.assignment_api.list_user_ids_for_project(
                        project['id']):
                    self.delete_tokens_for_user(user_id, project['id'])
        # TODO(morganfainberg): implement deletion of domain_scoped tokens.

        users = self.identity_api.list_users(domain_id)
        user_ids = (user['id'] for user in users)
        self.delete_tokens_for_users(user_ids)

    def delete_tokens_for_user(self, user_id, project_id=None):
        """Delete all tokens for a given user or user-project combination.

        This method adds in the extra logic for handling trust-scoped token
        revocations in a single call instead of needing to explicitly handle
        trusts in the caller's logic.
        """
        if not CONF.token.revoke_by_id:
            return
        self.delete_tokens(user_id, tenant_id=project_id)
        for trust in self.trust_api.list_trusts_for_trustee(user_id):
            # Ensure we revoke tokens associated to the trust / project
            # user_id combination.
            self.delete_tokens(user_id, trust_id=trust['id'],
                               tenant_id=project_id)
        for trust in self.trust_api.list_trusts_for_trustor(user_id):
            # Ensure we revoke tokens associated to the trust / project /
            # user_id combination where the user_id is the trustor.

            # NOTE(morganfainberg): This revocation is a bit coarse, but it
            # covers a number of cases such as disabling of the trustor user,
            # deletion of the trustor user (for any number of reasons). It
            # might make sense to refine this and be more surgical on the
            # deletions (e.g. don't revoke tokens for the trusts when the
            # trustor changes password). For now, to maintain previous
            # functionality, this will continue to be a bit overzealous on
            # revocations.
            self.delete_tokens(trust['trustee_user_id'], trust_id=trust['id'],
                               tenant_id=project_id)

    def delete_tokens_for_users(self, user_ids, project_id=None):
        """Delete all tokens for a list of user_ids.

        :param user_ids: list of user identifiers
        :param project_id: optional project identifier
        """
        if not CONF.token.revoke_by_id:
            return
        for user_id in user_ids:
            self.delete_tokens_for_user(user_id, project_id=project_id)

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


@dependency.requires('token_provider_api')
@dependency.provider('token_api')
class Manager(object):
    """The token_api provider.

    This class is a proxy class to the token_provider_api's persistence
    manager.
    """
    def __init__(self):
        # NOTE(morganfainberg): __init__ is required for dependency processing.
        super(Manager, self).__init__()

    def __getattr__(self, item):
        """Forward calls to the `token_provider_api` persistence manager."""

        # NOTE(morganfainberg): Prevent infinite recursion, raise an
        # AttributeError for 'token_provider_api' ensuring that the dep
        # injection doesn't infinitely try and lookup self.token_provider_api
        # on _process_dependencies. This doesn't need an exception string as
        # it should only ever be hit on instantiation.
        if item == 'token_provider_api':
            raise AttributeError()

        f = getattr(self.token_provider_api._persistence, item)
        LOG.warning(_LW('`token_api.%s` is deprecated as of Juno in favor of '
                        'utilizing methods on `token_provider_api` and may be '
                        'removed in Kilo.'), item)
        setattr(self, item, f)
        return f


@six.add_metaclass(abc.ABCMeta)
class TokenDriverV8(object):
    """Interface description for a Token driver."""

    @abc.abstractmethod
    def get_token(self, token_id):
        """Get a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: token_ref
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

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
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_token(self, token_id):
        """Deletes a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: None.
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

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
        :returns: The tokens that have been deleted.
        :raises: keystone.exception.TokenNotFound

        """
        if not CONF.token.revoke_by_id:
            return
        token_list = self._list_tokens(user_id,
                                       tenant_id=tenant_id,
                                       trust_id=trust_id,
                                       consumer_id=consumer_id)

        for token in token_list:
            try:
                self.delete_token(token)
            except exception.NotFound:
                pass
        return token_list

    @abc.abstractmethod
    def _list_tokens(self, user_id, tenant_id=None, trust_id=None,
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
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_revoked_tokens(self):
        """Returns a list of all revoked tokens

        :returns: list of token_id's

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def flush_expired_tokens(self):
        """Archive or delete tokens that have expired.
        """
        raise exception.NotImplemented()  # pragma: no cover


Driver = manager.create_legacy_driver(TokenDriverV8)

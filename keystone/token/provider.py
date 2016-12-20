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

"""Token provider interface."""

import datetime
import sys

from oslo_log import log
from oslo_utils import timeutils
import six

from keystone.common import cache
from keystone.common import dependency
from keystone.common import manager
import keystone.conf
from keystone import exception
from keystone.i18n import _, _LE
from keystone.models import token_model
from keystone import notifications
from keystone.token import persistence


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

TOKENS_REGION = cache.create_region(name='tokens')
MEMOIZE_TOKENS = cache.get_memoization_decorator(
    group='token',
    region=TOKENS_REGION)

# NOTE(morganfainberg): This is for compatibility in case someone was relying
# on the old location of the UnsupportedTokenVersionException for their code.
UnsupportedTokenVersionException = exception.UnsupportedTokenVersionException

# supported token versions
V2 = token_model.V2
V3 = token_model.V3
VERSIONS = token_model.VERSIONS


@dependency.provider('token_provider_api')
@dependency.requires('assignment_api', 'revoke_api')
class Manager(manager.Manager):
    """Default pivot point for the token provider backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.token.provider'

    V2 = V2
    V3 = V3
    VERSIONS = VERSIONS
    INVALIDATE_PROJECT_TOKEN_PERSISTENCE = 'invalidate_project_tokens'
    INVALIDATE_USER_TOKEN_PERSISTENCE = 'invalidate_user_tokens'
    _persistence_manager = None

    def __init__(self):
        super(Manager, self).__init__(CONF.token.provider)
        self._register_callback_listeners()

    def _register_callback_listeners(self):
        # This is used by the @dependency.provider decorator to register the
        # provider (token_provider_api) manager to listen for trust deletions.
        callbacks = {
            notifications.ACTIONS.deleted: [
                ['OS-TRUST:trust', self._trust_deleted_event_callback],
                ['user', self._delete_user_tokens_callback],
                ['domain', self._delete_domain_tokens_callback],
            ],
            notifications.ACTIONS.disabled: [
                ['user', self._delete_user_tokens_callback],
                ['domain', self._delete_domain_tokens_callback],
                ['project', self._delete_project_tokens_callback],
            ],
            notifications.ACTIONS.internal: [
                [notifications.INVALIDATE_USER_TOKEN_PERSISTENCE,
                    self._delete_user_tokens_callback],
                [notifications.INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE,
                    self._delete_user_project_tokens_callback],
                [notifications.INVALIDATE_USER_OAUTH_CONSUMER_TOKENS,
                    self._delete_user_oauth_consumer_tokens_callback],
            ]
        }

        for event, cb_info in callbacks.items():
            for resource_type, callback_fns in cb_info:
                notifications.register_event_callback(event, resource_type,
                                                      callback_fns)

    @property
    def _needs_persistence(self):
        return self.driver.needs_persistence()

    @property
    def _persistence(self):
        # NOTE(morganfainberg): This should not be handled via __init__ to
        # avoid dependency injection oddities circular dependencies (where
        # the provider manager requires the token persistence manager, which
        # requires the token provider manager).
        if self._persistence_manager is None:
            self._persistence_manager = persistence.PersistenceManager()
        return self._persistence_manager

    def _create_token(self, token_id, token_data):
        try:
            if isinstance(token_data['expires'], six.string_types):
                token_data['expires'] = timeutils.normalize_time(
                    timeutils.parse_isotime(token_data['expires']))
            self._persistence.create_token(token_id, token_data)
        except Exception:
            exc_info = sys.exc_info()
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self._persistence.get_token(token_id)
            except exception.TokenNotFound:
                six.reraise(*exc_info)

    def check_revocation_v2(self, token):
        try:
            token_data = token['access']
        except KeyError:
            raise exception.TokenNotFound(_('Failed to validate token'))

        token_values = self.revoke_api.model.build_token_values_v2(
            token_data, CONF.identity.default_domain_id)
        self.revoke_api.check_token(token_values)

    def check_revocation_v3(self, token):
        try:
            token_data = token['token']
        except KeyError:
            raise exception.TokenNotFound(_('Failed to validate token'))
        token_values = self.revoke_api.model.build_token_values(token_data)
        self.revoke_api.check_token(token_values)

    def check_revocation(self, token):
        version = self.get_token_version(token)
        if version == V2:
            return self.check_revocation_v2(token)
        else:
            return self.check_revocation_v3(token)

    def validate_token(self, token_id, window_seconds=0):
        if not token_id:
            raise exception.TokenNotFound(_('No token in the request'))

        try:
            # NOTE(lbragstad): Only go to persistent storage if we have a token
            # to fetch from the backend (the driver persists the token).
            # Otherwise the information about the token must be in the token
            # id.
            if self._needs_persistence:
                token_ref = self._persistence.get_token(token_id)
                # Overload the token_id variable to be a token reference
                # instead.
                token_id = token_ref
            token_ref = self._validate_token(token_id)
            self._is_valid_token(token_ref, window_seconds=window_seconds)
            return token_ref
        except exception.Unauthorized as e:
            LOG.debug('Unable to validate token: %s', e)
            raise exception.TokenNotFound(token_id=token_id)

    @MEMOIZE_TOKENS
    def _validate_token(self, token_id):
        return self.driver.validate_token(token_id)

    def _is_valid_token(self, token, window_seconds=0):
        """Verify the token is valid format and has not expired."""
        current_time = timeutils.normalize_time(timeutils.utcnow())

        try:
            # Get the data we need from the correct location (V2 and V3 tokens
            # differ in structure, Try V3 first, fall back to V2 second)
            token_data = token.get('token', token.get('access'))
            expires_at = token_data.get('expires_at',
                                        token_data.get('expires'))
            if not expires_at:
                expires_at = token_data['token']['expires']

            expiry = timeutils.parse_isotime(expires_at)
            expiry = timeutils.normalize_time(expiry)

            # add a window in which you can fetch a token beyond expiry
            expiry += datetime.timedelta(seconds=window_seconds)

        except Exception:
            LOG.exception(_LE('Unexpected error or malformed token '
                              'determining token expiry: %s'), token)
            raise exception.TokenNotFound(_('Failed to validate token'))

        if current_time < expiry:
            self.check_revocation(token)
            # Token has not expired and has not been revoked.
            return None
        else:
            raise exception.TokenNotFound(_('Failed to validate token'))

    def issue_token(self, user_id, method_names, expires_at=None,
                    project_id=None, is_domain=False, domain_id=None,
                    auth_context=None, trust=None, include_catalog=True,
                    parent_audit_id=None):
        token_id, token_data = self.driver.issue_token(
            user_id, method_names, expires_at, project_id, domain_id,
            auth_context, trust, include_catalog, parent_audit_id)

        data = dict(key=token_id,
                    id=token_id,
                    expires=token_data['token']['expires_at'],
                    user=token_data['token']['user'],
                    tenant=token_data['token'].get('project'),
                    is_domain=is_domain,
                    token_data=token_data,
                    trust_id=trust['id'] if trust else None,
                    token_version=self.V3)
        if self._needs_persistence:
            self._create_token(token_id, data)

        if CONF.token.cache_on_issue:
            # NOTE(amakarov): here and above TOKENS_REGION is to be passed
            # to serve as required positional "self" argument. It's ignored,
            # so I've put it here for convenience - any placeholder is fine.
            self._validate_token.set(token_data, TOKENS_REGION, token_id)

        return token_id, token_data

    def invalidate_individual_token_cache(self, token_id):
        # NOTE(morganfainberg): invalidate takes the exact same arguments as
        # the normal method, this means we need to pass "self" in (which gets
        # stripped off).

        # FIXME(morganfainberg): Does this cache actually need to be
        # invalidated? We maintain a cached revocation list, which should be
        # consulted before accepting a token as valid.  For now we will
        # do the explicit individual token invalidation.

        self._validate_token.invalidate(self, token_id)

    def revoke_token(self, token_id, revoke_chain=False):
        token_ref = token_model.KeystoneToken(
            token_id=token_id,
            token_data=self.validate_token(token_id))

        project_id = token_ref.project_id if token_ref.project_scoped else None
        domain_id = token_ref.domain_id if token_ref.domain_scoped else None

        if revoke_chain:
            self.revoke_api.revoke_by_audit_chain_id(token_ref.audit_chain_id,
                                                     project_id=project_id,
                                                     domain_id=domain_id)
        else:
            self.revoke_api.revoke_by_audit_id(token_ref.audit_id)

        if CONF.token.revoke_by_id and self._needs_persistence:
            self._persistence.delete_token(token_id=token_id)

        # FIXME(morganfainberg): Does this cache actually need to be
        # invalidated? We maintain a cached revocation list, which should be
        # consulted before accepting a token as valid.  For now we will
        # do the explicit individual token invalidation.
        self.invalidate_individual_token_cache(token_id)

    def list_revoked_tokens(self):
        return self._persistence.list_revoked_tokens()

    def _trust_deleted_event_callback(self, service, resource_type, operation,
                                      payload):
        if CONF.token.revoke_by_id:
            trust_id = payload['resource_info']
            trust = self.trust_api.get_trust(trust_id, deleted=True)
            self._persistence.delete_tokens(user_id=trust['trustor_user_id'],
                                            trust_id=trust_id)
        if CONF.token.cache_on_issue:
            # NOTE(amakarov): preserving behavior
            TOKENS_REGION.invalidate()

    def _delete_user_tokens_callback(self, service, resource_type, operation,
                                     payload):
        if CONF.token.revoke_by_id:
            user_id = payload['resource_info']
            self._persistence.delete_tokens_for_user(user_id)
        if CONF.token.cache_on_issue:
            # NOTE(amakarov): preserving behavior
            TOKENS_REGION.invalidate()

    def _delete_domain_tokens_callback(self, service, resource_type,
                                       operation, payload):
        if CONF.token.revoke_by_id:
            domain_id = payload['resource_info']
            self._persistence.delete_tokens_for_domain(domain_id=domain_id)
        if CONF.token.cache_on_issue:
            # NOTE(amakarov): preserving behavior
            TOKENS_REGION.invalidate()

    def _delete_user_project_tokens_callback(self, service, resource_type,
                                             operation, payload):
        if CONF.token.revoke_by_id:
            user_id = payload['resource_info']['user_id']
            project_id = payload['resource_info']['project_id']
            self._persistence.delete_tokens_for_user(user_id=user_id,
                                                     project_id=project_id)
        if CONF.token.cache_on_issue:
            # NOTE(amakarov): preserving behavior
            TOKENS_REGION.invalidate()

    def _delete_project_tokens_callback(self, service, resource_type,
                                        operation, payload):
        if CONF.token.revoke_by_id:
            project_id = payload['resource_info']
            self._persistence.delete_tokens_for_users(
                self.assignment_api.list_user_ids_for_project(project_id),
                project_id=project_id)
        if CONF.token.cache_on_issue:
            # NOTE(amakarov): preserving behavior
            TOKENS_REGION.invalidate()

    def _delete_user_oauth_consumer_tokens_callback(self, service,
                                                    resource_type, operation,
                                                    payload):
        if CONF.token.revoke_by_id:
            user_id = payload['resource_info']['user_id']
            consumer_id = payload['resource_info']['consumer_id']
            self._persistence.delete_tokens(user_id=user_id,
                                            consumer_id=consumer_id)
        if CONF.token.cache_on_issue:
            # NOTE(amakarov): preserving behavior
            TOKENS_REGION.invalidate()

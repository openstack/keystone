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

from oslo_log import log
from oslo_utils import timeutils

from keystone.common import cache
from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model
from keystone import notifications


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs

TOKENS_REGION = cache.create_region(name='tokens')
MEMOIZE_TOKENS = cache.get_memoization_decorator(
    group='token',
    region=TOKENS_REGION)

# NOTE(morganfainberg): This is for compatibility in case someone was relying
# on the old location of the UnsupportedTokenVersionException for their code.
UnsupportedTokenVersionException = exception.UnsupportedTokenVersionException

# supported token versions
V3 = token_model.V3
VERSIONS = token_model.VERSIONS


class Manager(manager.Manager):
    """Default pivot point for the token provider backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.token.provider'
    _provides_api = 'token_provider_api'

    V3 = V3
    VERSIONS = VERSIONS

    def __init__(self):
        super(Manager, self).__init__(CONF.token.provider)
        self._register_callback_listeners()

    def _register_callback_listeners(self):
        # This is used by the @dependency.provider decorator to register the
        # provider (token_provider_api) manager to listen for trust deletions.
        callbacks = {
            notifications.ACTIONS.deleted: [
                ['OS-TRUST:trust', self._drop_token_cache],
                ['user', self._drop_token_cache],
                ['domain', self._drop_token_cache],
            ],
            notifications.ACTIONS.disabled: [
                ['user', self._drop_token_cache],
                ['domain', self._drop_token_cache],
                ['project', self._drop_token_cache],
            ],
            notifications.ACTIONS.internal: [
                [notifications.INVALIDATE_TOKEN_CACHE,
                    self._drop_token_cache],
            ]
        }

        for event, cb_info in callbacks.items():
            for resource_type, callback_fns in cb_info:
                notifications.register_event_callback(event, resource_type,
                                                      callback_fns)

    def _drop_token_cache(self, service, resource_type, operation, payload):
        """Invalidate the entire token cache.

        This is a handy private utility method that should be used when
        consuming notifications that signal invalidating the token cache.

        """
        if CONF.token.cache_on_issue:
            TOKENS_REGION.invalidate()

    def check_revocation_v3(self, token):
        try:
            token_data = token['token']
        except KeyError:
            raise exception.TokenNotFound(_('Failed to validate token'))
        token_values = self.revoke_api.model.build_token_values(token_data)
        PROVIDERS.revoke_api.check_token(token_values)

    def check_revocation(self, token):
        return self.check_revocation_v3(token)

    def validate_token(self, token_id, window_seconds=0):
        if not token_id:
            raise exception.TokenNotFound(_('No token in the request'))

        try:
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
            LOG.exception('Unexpected error or malformed token '
                          'determining token expiry: %s', token)
            raise exception.TokenNotFound(_('Failed to validate token'))

        if current_time < expiry:
            self.check_revocation(token)
            # Token has not expired and has not been revoked.
            return None
        else:
            raise exception.TokenNotFound(_('Failed to validate token'))

    def issue_token(self, user_id, method_names, expires_at=None,
                    system=None, project_id=None, is_domain=False,
                    domain_id=None, auth_context=None, trust=None,
                    app_cred_id=None, include_catalog=True,
                    parent_audit_id=None):
        token_id, token_data = self.driver.issue_token(
            user_id, method_names, expires_at=expires_at,
            system=system, project_id=project_id,
            domain_id=domain_id, auth_context=auth_context, trust=trust,
            app_cred_id=app_cred_id, include_catalog=include_catalog,
            parent_audit_id=parent_audit_id)

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
            PROVIDERS.revoke_api.revoke_by_audit_chain_id(
                token_ref.audit_chain_id, project_id=project_id,
                domain_id=domain_id
            )
        else:
            PROVIDERS.revoke_api.revoke_by_audit_id(token_ref.audit_id)

        # FIXME(morganfainberg): Does this cache actually need to be
        # invalidated? We maintain a cached revocation list, which should be
        # consulted before accepting a token as valid.  For now we will
        # do the explicit individual token invalidation.
        self.invalidate_individual_token_cache(token_id)

    def list_revoked_tokens(self):
        # FIXME(lbragstad): In the future, the token providers are going to be
        # responsible for handling persistence if they require it (e.g. token
        # providers not doing some sort of authenticated encryption strategy).
        # When that happens, we could still expose this API by checking an
        # interface on the provider can calling it if available. For now, this
        # will return a valid response, but it will just be an empty list. See
        # http://paste.openstack.org/raw/670196/ for and example using
        # keystoneclient.common.cms to verify the response.
        return []

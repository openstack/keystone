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

import base64
import datetime
import uuid

from oslo_log import log
from oslo_utils import timeutils

from keystone.common import cache
from keystone.common import manager
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.federation import constants
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

# minimum access rules support
ACCESS_RULES_MIN_VERSION = token_model.ACCESS_RULES_MIN_VERSION


def default_expire_time():
    """Determine when a fresh token should expire.

    Expiration time varies based on configuration (see ``[token] expiration``).

    :returns: a naive UTC datetime.datetime object

    """
    expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
    expires_at = timeutils.utcnow() + expire_delta
    return expires_at.replace(microsecond=0)


def random_urlsafe_str():
    """Generate a random URL-safe string.

    :rtype: str
    """
    # chop the padding (==) off the end of the encoding to save space
    return base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2].decode('utf-8')


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
        if CONF.token.cache_on_issue or CONF.token.caching:
            TOKENS_REGION.invalidate()

    def check_revocation_v3(self, token):
        token_values = self.revoke_api.model.build_token_values(token)
        PROVIDERS.revoke_api.check_token(token_values)

    def check_revocation(self, token):
        return self.check_revocation_v3(token)

    def validate_token(self, token_id, window_seconds=0,
                       access_rules_support=None):
        if not token_id:
            raise exception.TokenNotFound(_('No token in the request'))

        try:
            token = self._validate_token(token_id)
            self._is_valid_token(token, window_seconds=window_seconds)
            self._validate_token_access_rules(token, access_rules_support)
            return token
        except exception.Unauthorized as e:
            LOG.debug('Unable to validate token: %s', e)
            raise exception.TokenNotFound(token_id=token_id)

    @MEMOIZE_TOKENS
    def _validate_token(self, token_id):
        (user_id, methods, audit_ids, system, domain_id,
            project_id, trust_id, federated_group_ids, identity_provider_id,
            protocol_id, access_token_id, app_cred_id, issued_at,
            expires_at) = self.driver.validate_token(token_id)

        token = token_model.TokenModel()
        token.user_id = user_id
        token.methods = methods
        if len(audit_ids) > 1:
            token.parent_audit_id = audit_ids.pop()
        token.audit_id = audit_ids.pop()
        token.system = system
        token.domain_id = domain_id
        token.project_id = project_id
        token.trust_id = trust_id
        token.access_token_id = access_token_id
        token.application_credential_id = app_cred_id
        token.expires_at = expires_at
        if federated_group_ids is not None:
            token.is_federated = True
            token.identity_provider_id = identity_provider_id
            token.protocol_id = protocol_id
            token.federated_groups = federated_group_ids

        token.mint(token_id, issued_at)
        return token

    def _is_valid_token(self, token, window_seconds=0):
        """Verify the token is valid format and has not expired."""
        current_time = timeutils.normalize_time(timeutils.utcnow())

        try:
            expiry = timeutils.parse_isotime(token.expires_at)
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

    def _validate_token_access_rules(self, token, access_rules_support=None):
        if token.application_credential_id:
            app_cred_api = PROVIDERS.application_credential_api
            app_cred = app_cred_api.get_application_credential(
                token.application_credential_id)
            if (app_cred.get('access_rules') is not None and
                (not access_rules_support or
                 (float(access_rules_support) < ACCESS_RULES_MIN_VERSION))):
                LOG.exception('Attempted to use application credential'
                              ' access rules with a middleware that does not'
                              ' understand them. You must upgrade'
                              ' keystonemiddleware on all services that'
                              ' accept application credentials as an'
                              ' authentication method.')
                raise exception.TokenNotFound(_('Failed to validate token'))

    def issue_token(self, user_id, method_names, expires_at=None,
                    system=None, project_id=None, domain_id=None,
                    auth_context=None, trust_id=None, app_cred_id=None,
                    parent_audit_id=None):

        # NOTE(lbragstad): Grab a blank token object and use composition to
        # build the token according to the authentication and authorization
        # context. This cuts down on the amount of logic we have to stuff into
        # the TokenModel's __init__() method.
        token = token_model.TokenModel()
        token.methods = method_names
        token.system = system
        token.domain_id = domain_id
        token.project_id = project_id
        token.trust_id = trust_id
        token.application_credential_id = app_cred_id
        token.audit_id = random_urlsafe_str()
        token.parent_audit_id = parent_audit_id

        if auth_context:
            if constants.IDENTITY_PROVIDER in auth_context:
                token.is_federated = True
                token.protocol_id = auth_context[constants.PROTOCOL]
                idp_id = auth_context[constants.IDENTITY_PROVIDER]
                if isinstance(idp_id, bytes):
                    idp_id = idp_id.decode('utf-8')
                token.identity_provider_id = idp_id
                token.user_id = auth_context['user_id']
                token.federated_groups = [
                    {'id': group} for group in auth_context['group_ids']
                ]

            if 'access_token_id' in auth_context:
                token.access_token_id = auth_context['access_token_id']

        if not token.user_id:
            token.user_id = user_id

        token.user_domain_id = token.user['domain_id']

        if isinstance(expires_at, datetime.datetime):
            token.expires_at = utils.isotime(expires_at, subsecond=True)
        if isinstance(expires_at, str):
            token.expires_at = expires_at
        elif not expires_at:
            token.expires_at = utils.isotime(
                default_expire_time(), subsecond=True
            )

        token_id, issued_at = self.driver.generate_id_and_issued_at(token)
        token.mint(token_id, issued_at)

        # cache the token object and with ID
        if CONF.token.cache_on_issue or CONF.token.caching:
            # NOTE(amakarov): here and above TOKENS_REGION is to be passed
            # to serve as required positional "self" argument. It's ignored,
            # so I've put it here for convenience - any placeholder is fine.
            self._validate_token.set(token, self, token.id)

        return token

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
        token = self.validate_token(token_id)

        project_id = token.project_id if token.project_scoped else None
        domain_id = token.domain_id if token.domain_scoped else None

        if revoke_chain:
            PROVIDERS.revoke_api.revoke_by_audit_chain_id(
                token.parent_audit_id, project_id=project_id,
                domain_id=domain_id
            )
        else:
            PROVIDERS.revoke_api.revoke_by_audit_id(token.audit_id)

        # FIXME(morganfainberg): Does this cache actually need to be
        # invalidated? We maintain a cached revocation list, which should be
        # consulted before accepting a token as valid.  For now we will
        # do the explicit individual token invalidation.
        self.invalidate_individual_token_cache(token_id)

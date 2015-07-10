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

"""Unified in-memory token model."""

from keystoneclient.common import cms
from oslo_config import cfg
from oslo_utils import timeutils
import six

from keystone.contrib.federation import constants as federation_constants
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
# supported token versions
V2 = 'v2.0'
V3 = 'v3.0'
VERSIONS = frozenset([V2, V3])


def _parse_and_normalize_time(time_data):
    if isinstance(time_data, six.string_types):
        time_data = timeutils.parse_isotime(time_data)
    return timeutils.normalize_time(time_data)


class KeystoneToken(dict):
    """An in-memory representation that unifies v2 and v3 tokens."""
    # TODO(morganfainberg): Align this in-memory representation with the
    # objects in keystoneclient. This object should be eventually updated
    # to be the source of token data with the ability to emit any version
    # of the token instead of only consuming the token dict and providing
    # property accessors for the underlying data.

    def __init__(self, token_id, token_data):
        self.token_data = token_data
        if 'access' in token_data:
            super(KeystoneToken, self).__init__(**token_data['access'])
            self.version = V2
        elif 'token' in token_data and 'methods' in token_data['token']:
            super(KeystoneToken, self).__init__(**token_data['token'])
            self.version = V3
        else:
            raise exception.UnsupportedTokenVersionException()
        self.token_id = token_id
        self.short_id = cms.cms_hash_token(token_id,
                                           mode=CONF.token.hash_algorithm)

        if self.project_scoped and self.domain_scoped:
            raise exception.UnexpectedError(_('Found invalid token: scoped to '
                                              'both project and domain.'))

    def __repr__(self):
        desc = ('<%(type)s (audit_id=%(audit_id)s, '
                'audit_chain_id=%(audit_chain_id)s) at %(loc)s>')
        return desc % {'type': self.__class__.__name__,
                       'audit_id': self.audit_id,
                       'audit_chain_id': self.audit_chain_id,
                       'loc': hex(id(self))}

    @property
    def expires(self):
        if self.version is V3:
            expires_at = self['expires_at']
        else:
            expires_at = self['token']['expires']
        return _parse_and_normalize_time(expires_at)

    @property
    def issued(self):
        if self.version is V3:
            issued_at = self['issued_at']
        else:
            issued_at = self['token']['issued_at']
        return _parse_and_normalize_time(issued_at)

    @property
    def audit_id(self):
        if self.version is V3:
            return self.get('audit_ids', [None])[0]
        return self['token'].get('audit_ids', [None])[0]

    @property
    def audit_chain_id(self):
        if self.version is V3:
            return self.get('audit_ids', [None])[-1]
        return self['token'].get('audit_ids', [None])[-1]

    @property
    def auth_token(self):
        return self.token_id

    @property
    def user_id(self):
        return self['user']['id']

    @property
    def user_name(self):
        return self['user']['name']

    @property
    def user_domain_name(self):
        try:
            if self.version == V3:
                return self['user']['domain']['name']
            elif 'user' in self:
                return "Default"
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def user_domain_id(self):
        try:
            if self.version == V3:
                return self['user']['domain']['id']
            elif 'user' in self:
                return CONF.identity.default_domain_id
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def domain_id(self):
        if self.version is V3:
            try:
                return self['domain']['id']
            except KeyError:
                # Do not raise KeyError, raise UnexpectedError
                raise exception.UnexpectedError()
        # No domain scoped tokens in V2.
        raise NotImplementedError()

    @property
    def domain_name(self):
        if self.version is V3:
            try:
                return self['domain']['name']
            except KeyError:
                # Do not raise KeyError, raise UnexpectedError
                raise exception.UnexpectedError()
        # No domain scoped tokens in V2.
        raise NotImplementedError()

    @property
    def project_id(self):
        try:
            if self.version is V3:
                return self['project']['id']
            else:
                return self['token']['tenant']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_name(self):
        try:
            if self.version is V3:
                return self['project']['name']
            else:
                return self['token']['tenant']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_domain_id(self):
        try:
            if self.version is V3:
                return self['project']['domain']['id']
            elif 'tenant' in self['token']:
                return CONF.identity.default_domain_id
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass

        raise exception.UnexpectedError()

    @property
    def project_domain_name(self):
        try:
            if self.version is V3:
                return self['project']['domain']['name']
            if 'tenant' in self['token']:
                return 'Default'
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass

        raise exception.UnexpectedError()

    @property
    def project_scoped(self):
        if self.version is V3:
            return 'project' in self
        else:
            return 'tenant' in self['token']

    @property
    def domain_scoped(self):
        if self.version is V3:
            return 'domain' in self
        return False

    @property
    def scoped(self):
        return self.project_scoped or self.domain_scoped

    @property
    def trust_id(self):
        if self.version is V3:
            return self.get('OS-TRUST:trust', {}).get('id')
        else:
            return self.get('trust', {}).get('id')

    @property
    def trust_scoped(self):
        if self.version is V3:
            return 'OS-TRUST:trust' in self
        else:
            return 'trust' in self

    @property
    def trustee_user_id(self):
        if self.version is V3:
            return self.get(
                'OS-TRUST:trust', {}).get('trustee_user_id')
        else:
            return self.get('trust', {}).get('trustee_user_id')

    @property
    def trustor_user_id(self):
        if self.version is V3:
            return self.get(
                'OS-TRUST:trust', {}).get('trustor_user_id')
        else:
            return self.get('trust', {}).get('trustor_user_id')

    @property
    def trust_impersonation(self):
        if self.version is V3:
            return self.get('OS-TRUST:trust', {}).get('impersonation')
        else:
            return self.get('trust', {}).get('impersonation')

    @property
    def oauth_scoped(self):
        return 'OS-OAUTH1' in self

    @property
    def oauth_access_token_id(self):
        if self.version is V3 and self.oauth_scoped:
            return self['OS-OAUTH1']['access_token_id']
        return None

    @property
    def oauth_consumer_id(self):
        if self.version is V3 and self.oauth_scoped:
            return self['OS-OAUTH1']['consumer_id']
        return None

    @property
    def role_ids(self):
        if self.version is V3:
            return [r['id'] for r in self.get('roles', [])]
        else:
            return self.get('metadata', {}).get('roles', [])

    @property
    def role_names(self):
        if self.version is V3:
            return [r['name'] for r in self.get('roles', [])]
        else:
            return [r['name'] for r in self['user'].get('roles', [])]

    @property
    def bind(self):
        if self.version is V3:
            return self.get('bind')
        return self.get('token', {}).get('bind')

    @property
    def is_federated_user(self):
        try:
            return (self.version is V3 and
                    federation_constants.FEDERATION in self['user'])
        except KeyError:
            raise exception.UnexpectedError()

    @property
    def federation_group_ids(self):
        if self.is_federated_user:
            if self.version is V3:
                try:
                    groups = self['user'][federation_constants.FEDERATION].get(
                        'groups', [])
                    return [g['id'] for g in groups]
                except KeyError:
                    raise exception.UnexpectedError()
        return []

    @property
    def federation_idp_id(self):
        if self.version is not V3 or not self.is_federated_user:
            return None
        return (
            self['user'][federation_constants.FEDERATION]
            ['identity_provider']['id'])

    @property
    def federation_protocol_id(self):
        if self.version is V3 and self.is_federated_user:
            return (self['user'][federation_constants.FEDERATION]['protocol']
                    ['id'])
        return None

    @property
    def metadata(self):
        return self.get('metadata', {})

    @property
    def methods(self):
        if self.version is V3:
            return self.get('methods', [])
        return []

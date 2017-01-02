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

from oslo_utils import reflection
from oslo_utils import timeutils
import six

import keystone.conf
from keystone import exception
from keystone.federation import constants
from keystone.i18n import _

CONF = keystone.conf.CONF
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
        self.token_id = token_id
        try:
            super(KeystoneToken, self).__init__(**token_data['token'])
        except KeyError:
            raise exception.UnsupportedTokenVersionException()
        self.token_id = token_id

        if self.project_scoped and self.domain_scoped:
            raise exception.UnexpectedError(_('Found invalid token: scoped to '
                                              'both project and domain.'))

    def __repr__(self):
        """Return string representation of KeystoneToken."""
        desc = ('<%(type)s (audit_id=%(audit_id)s, '
                'audit_chain_id=%(audit_chain_id)s) at %(loc)s>')
        self_cls_name = reflection.get_class_name(self,
                                                  fully_qualified=False)
        return desc % {'type': self_cls_name,
                       'audit_id': self.audit_id,
                       'audit_chain_id': self.audit_chain_id,
                       'loc': hex(id(self))}

    @property
    def expires(self):
        return _parse_and_normalize_time(self['expires_at'])

    @property
    def issued(self):
        return _parse_and_normalize_time(self['issued_at'])

    @property
    def audit_id(self):
        return self.get('audit_ids', [None])[0]

    @property
    def audit_chain_id(self):
        return self.get('audit_ids', [None])[-1]

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
            return self['user']['domain']['name']
        except KeyError:  # nosec
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def user_password_expires_at(self):
        try:
            return self['user']['password_expires_at']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def user_domain_id(self):
        try:
            return self['user']['domain']['id']
        except KeyError:  # nosec
            # Do not raise KeyError, raise UnexpectedError
            pass
        raise exception.UnexpectedError()

    @property
    def domain_id(self):
        try:
            return self['domain']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def domain_name(self):
        try:
            return self['domain']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_id(self):
        try:
            return self['project']['id']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_name(self):
        try:
            return self['project']['name']
        except KeyError:
            # Do not raise KeyError, raise UnexpectedError
            raise exception.UnexpectedError()

    @property
    def project_domain_id(self):
        try:
            return self['project']['domain']['id']
        except KeyError:  # nosec
            # Do not raise KeyError, raise UnexpectedError
            pass

        raise exception.UnexpectedError()

    @property
    def project_domain_name(self):
        try:
            return self['project']['domain']['name']
        except KeyError:  # nosec
            # Do not raise KeyError, raise UnexpectedError
            pass

        raise exception.UnexpectedError()

    @property
    def is_domain(self):
        if 'is_domain' in self:
            return self['is_domain']
        return False

    @property
    def project_scoped(self):
        return 'project' in self

    @property
    def domain_scoped(self):
        return 'domain' in self

    @property
    def scoped(self):
        return self.project_scoped or self.domain_scoped

    @property
    def is_admin_project(self):
        if self.domain_scoped:
            # Currently, domain scoped tokens cannot act as is_admin_project
            return False

        # True gets returned by default for compatibility with older versions
        # TODO(henry-nash): This seems inherently dangerous, and we should
        # investigate how we can default this to False.
        return self.get('is_admin_project', True)

    @property
    def trust_id(self):
        return self.get('OS-TRUST:trust', {}).get('id')

    @property
    def trust_scoped(self):
        return 'OS-TRUST:trust' in self

    @property
    def trustee_user_id(self):
        return self.get('OS-TRUST:trust', {}).get('trustee_user_id')

    @property
    def trustor_user_id(self):
        return self.get('OS-TRUST:trust', {}).get('trustor_user_id')

    @property
    def trust_impersonation(self):
        return self.get('OS-TRUST:trust', {}).get('impersonation')

    @property
    def oauth_scoped(self):
        return 'OS-OAUTH1' in self

    @property
    def oauth_access_token_id(self):
        if self.oauth_scoped:
            return self['OS-OAUTH1']['access_token_id']
        return None

    @property
    def oauth_consumer_id(self):
        if self.oauth_scoped:
            return self['OS-OAUTH1']['consumer_id']
        return None

    @property
    def role_ids(self):
        return [r['id'] for r in self.get('roles', [])]

    @property
    def role_names(self):
        return [r['name'] for r in self.get('roles', [])]

    @property
    def bind(self):
        return self.get('bind')

    @property
    def is_federated_user(self):
        try:
            return constants.FEDERATION in self['user']
        except KeyError:
            raise exception.UnexpectedError()

    @property
    def federation_group_ids(self):
        if self.is_federated_user:
            try:
                groups = self['user'][constants.FEDERATION].get('groups', [])
                return [g['id'] for g in groups]
            except KeyError:
                raise exception.UnexpectedError()
        return []

    @property
    def federation_idp_id(self):
        if self.is_federated_user:
            return (
                self['user'][constants.FEDERATION]['identity_provider']['id']
            )

    @property
    def federation_protocol_id(self):
        if self.is_federated_user:
            return self['user'][constants.FEDERATION]['protocol']['id']
        return None

    @property
    def metadata(self):
        return self.get('metadata', {})

    @property
    def methods(self):
        return self.get('methods', [])

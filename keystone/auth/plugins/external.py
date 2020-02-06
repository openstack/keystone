# Copyright 2013 OpenStack Foundation
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

"""Keystone External Authentication Plugins."""

import abc

import flask

from keystone.auth.plugins import base
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class Base(base.AuthMethodHandler, metaclass=abc.ABCMeta):
    def authenticate(self, auth_payload):
        """Use REMOTE_USER to look up the user in the identity backend.

        The user_id from the actual user from the REMOTE_USER env variable is
        placed in the response_data.
        """
        response_data = {}
        if not flask.request.remote_user:
            msg = _('No authenticated user')
            raise exception.Unauthorized(msg)

        try:
            user_ref = self._authenticate()
        except Exception:
            msg = _('Unable to lookup user %s') % flask.request.remote_user
            raise exception.Unauthorized(msg)

        response_data['user_id'] = user_ref['id']
        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)

    @abc.abstractmethod
    def _authenticate(self):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass


class DefaultDomain(Base):
    def _authenticate(self):
        """Use remote_user to look up the user in the identity backend."""
        return PROVIDERS.identity_api.get_user_by_name(
            flask.request.remote_user,
            CONF.identity.default_domain_id)


class Domain(Base):
    def _authenticate(self):
        """Use remote_user to look up the user in the identity backend.

        The domain will be extracted from the REMOTE_DOMAIN environment
        variable if present. If not, the default domain will be used.
        """
        remote_domain = flask.request.environ.get('REMOTE_DOMAIN')
        if remote_domain:
            ref = PROVIDERS.resource_api.get_domain_by_name(remote_domain)
            domain_id = ref['id']
        else:
            domain_id = CONF.identity.default_domain_id

        return PROVIDERS.identity_api.get_user_by_name(
            flask.request.remote_user, domain_id)


class KerberosDomain(Domain):
    """Allows `kerberos` as a method."""

    def _authenticate(self):
        if flask.request.environ.get('AUTH_TYPE') != 'Negotiate':
            raise exception.Unauthorized(_("auth_type is not Negotiate"))
        return super(KerberosDomain, self)._authenticate()

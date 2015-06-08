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

"""Keystone External Authentication Plugins"""

import abc

from oslo_config import cfg
import six

from keystone import auth
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF


@six.add_metaclass(abc.ABCMeta)
class Base(auth.AuthMethodHandler):
    def authenticate(self, context, auth_info, auth_context):
        """Use REMOTE_USER to look up the user in the identity backend.

        auth_context is an in-out variable that will be updated with the
        user_id from the actual user from the REMOTE_USER env variable.
        """
        try:
            REMOTE_USER = context['environment']['REMOTE_USER']
        except KeyError:
            msg = _('No authenticated user')
            raise exception.Unauthorized(msg)
        try:
            user_ref = self._authenticate(REMOTE_USER, context)
            auth_context['user_id'] = user_ref['id']
            if ('kerberos' in CONF.token.bind and
                (context['environment'].get('AUTH_TYPE', '').lower()
                 == 'negotiate')):
                auth_context['bind']['kerberos'] = user_ref['name']
        except Exception:
            msg = _('Unable to lookup user %s') % (REMOTE_USER)
            raise exception.Unauthorized(msg)

    @abc.abstractmethod
    def _authenticate(self, remote_user, context):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass


@dependency.requires('identity_api')
class DefaultDomain(Base):
    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend."""
        domain_id = CONF.identity.default_domain_id
        user_ref = self.identity_api.get_user_by_name(remote_user, domain_id)
        return user_ref


@dependency.requires('identity_api', 'resource_api')
class Domain(Base):
    def _authenticate(self, remote_user, context):
        """Use remote_user to look up the user in the identity backend.

        The domain will be extracted from the REMOTE_DOMAIN environment
        variable if present. If not, the default domain will be used.
        """

        username = remote_user
        try:
            domain_name = context['environment']['REMOTE_DOMAIN']
        except KeyError:
            domain_id = CONF.identity.default_domain_id
        else:
            domain_ref = self.resource_api.get_domain_by_name(domain_name)
            domain_id = domain_ref['id']

        user_ref = self.identity_api.get_user_by_name(username, domain_id)
        return user_ref


class KerberosDomain(Domain):
    """Allows `kerberos` as a method."""
    def _authenticate(self, remote_user, context):
        auth_type = context['environment'].get('AUTH_TYPE')
        if auth_type != 'Negotiate':
            raise exception.Unauthorized(_("auth_type is not Negotiate"))
        return super(KerberosDomain, self)._authenticate(remote_user, context)

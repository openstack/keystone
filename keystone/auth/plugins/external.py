# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

"""Keystone External Authentication Plugin"""

import abc

import six

from keystone import auth
from keystone.common import config
from keystone import exception
from keystone.openstack.common import log as logging


LOG = logging.getLogger(__name__)

CONF = config.CONF


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
            user_ref = self._authenticate(REMOTE_USER, auth_info)
            auth_context['user_id'] = user_ref['id']
            if ('kerberos' in CONF.token.bind and
                (context['environment'].get('AUTH_TYPE', '').lower()
                 == 'negotiate')):
                auth_context['bind']['kerberos'] = user_ref['name']
        except Exception:
            msg = _('Unable to lookup user %s') % (REMOTE_USER)
            raise exception.Unauthorized(msg)

    @abc.abstractmethod
    def _authenticate(self, remote_user):
        """Look up the user in the identity backend.

        Return user_ref
        """
        pass


class Default(Base):
    def _authenticate(self, remote_user, auth_info):
        """Use remote_user to look up the user in the identity backend."""
        names = remote_user.split('@')
        username = names.pop(0)
        domain_id = CONF.identity.default_domain_id
        user_ref = auth_info.identity_api.get_user_by_name(username,
                                                           domain_id)
        return user_ref


class Domain(Base):
    def _authenticate(self, remote_user, auth_info):
        """Use remote_user to look up the user in the identity backend.

        If remote_user contains an `@` assume that the substring before the
        rightmost `@` is the username, and the substring after the @ is the
        domain name.
        """
        names = remote_user.rsplit('@', 1)
        username = names.pop(0)
        if names:
            domain_name = names[0]
            domain_ref = (auth_info.assignment_api.
                          get_domain_by_name(domain_name))
            domain_id = domain_ref['id']
        else:
            domain_id = CONF.identity.default_domain_id
        user_ref = auth_info.identity_api.get_user_by_name(username,
                                                           domain_id)
        return user_ref


# NOTE(aloga): ExternalDefault and External have been renamed to Default and
# Domain.
class ExternalDefault(Default):
    """Deprecated. Please use keystone.auth.external.Default instead."""
    def __init__(self):
        msg = _('keystone.auth.external.ExternalDefault is deprecated in'
                'favor of keystone.auth.external.Default')
        LOG.warning(msg)


class ExternalDomain(Domain):
    """Deprecated. Please use keystone.auth.external.Domain instead."""
    def __init__(self):
        msg = _('keystone.auth.external.ExternalDomain is deprecated in'
                'favor of keystone.auth.external.Domain')
        LOG.warning(msg)

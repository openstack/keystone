# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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

from keystone.common import config
from keystone import exception


CONF = config.CONF


class ExternalDefault(object):
    def authenticate(self, context, auth_info, auth_context):
        """Use REMOTE_USER to look up the user in the identity backend

        auth_context is an in-out variable that will be updated with the
        username from the REMOTE_USER environment variable.
        """
        try:
            REMOTE_USER = context['REMOTE_USER']
        except KeyError:
            msg = _('No authenticated user')
            raise exception.Unauthorized(msg)
        try:
            names = REMOTE_USER.split('@')
            username = names.pop(0)
            domain_id = CONF.identity.default_domain_id
            user_ref = auth_info.identity_api.get_user_by_name(username,
                                                               domain_id)
            auth_context['user_id'] = user_ref['id']
            if ('kerberos' in CONF.token.bind and
                    context.get('AUTH_TYPE', '').lower() == 'negotiate'):
                auth_context['bind']['kerberos'] = username
        except Exception:
            msg = _('Unable to lookup user %s') % (REMOTE_USER)
            raise exception.Unauthorized(msg)


class ExternalDomain(object):
    def authenticate(self, context, auth_info, auth_context):
        """Use REMOTE_USER to look up the user in the identity backend

        auth_context is an in-out variable that will be updated with the
        username from the REMOTE_USER environment variable.

        If REMOTE_USER contains an `@` assume that the substring before the
        rightmost `@` is the username, and the substring after the @ is the
        domain name.
        """
        try:
            REMOTE_USER = context['REMOTE_USER']
        except KeyError:
            msg = _('No authenticated user')
            raise exception.Unauthorized(msg)
        try:
            names = REMOTE_USER.rsplit('@', 1)
            username = names.pop(0)
            if names:
                domain_name = names[0]
                domain_ref = (auth_info.identity_api.
                              get_domain_by_name(domain_name))
                domain_id = domain_ref['id']
            else:
                domain_id = CONF.identity.default_domain_id
            user_ref = auth_info.identity_api.get_user_by_name(username,
                                                               domain_id)
            auth_context['user_id'] = user_ref['id']
            if ('kerberos' in CONF.token.bind and
                    context.get('AUTH_TYPE', '').lower() == 'negotiate'):
                auth_context['bind']['kerberos'] = username

        except Exception:
            msg = _('Unable to lookup user %s') % (REMOTE_USER)
            raise exception.Unauthorized(msg)

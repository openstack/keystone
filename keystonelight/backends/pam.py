# vim: tabstop=4 shiftwidth=4 softtabstop=4

from __future__ import absolute_import

import pam


class PamIdentity(object):
    """Very basic identity based on PAM.

    Tenant is always the same as User, root user has admin role.
    """

    def authenticate(self, username, password, **kwargs):
        if pam.authenticate(username, password):
            extras = {}
            if username == 'root':
                extras['is_admin'] == True

            tenant = {'id': username,
                      'name': username}
            user = {'id': username,
                    'name': username}

            return (tenant, user, extras)

    def get_tenants(self, username):
        return [{'id': username,
                 'name': username}]

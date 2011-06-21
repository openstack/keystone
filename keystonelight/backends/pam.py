# vim: tabstop=4 shiftwidth=4 softtabstop=4

from __future__ import absolute_imports

import pam


class PamIdentity(object):
    """Very basic identity based on PAM.

    Tenant is always the same as User, root user has admin role.
    """

    def authenticate(self, username, password):
        if pam.authenticate(username, password):
            extras = {}
            if username == 'root':
                extras['is_admin'] == True
            # NOTE(termie): (tenant, user, extras)
            return (username, username, extras)


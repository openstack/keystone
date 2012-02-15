# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from __future__ import absolute_import

import pam


class PamIdentity(object):
    """Very basic identity based on PAM.

    Tenant is always the same as User, root user has admin role.
    """

    def authenticate(self, username, password, **kwargs):
        if pam.authenticate(username, password):
            metadata = {}
            if username == 'root':
                metadata['is_admin'] == True

            tenant = {'id': username,
                      'name': username}
            user = {'id': username,
                    'name': username}

            return (tenant, user, metadata)

    def get_tenants(self, username):
        return [{'id': username,
                 'name': username}]

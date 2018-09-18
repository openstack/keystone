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

from keystone.auth import plugins as auth_plugins
from keystone.auth.plugins import base
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _


METHOD_NAME = 'password'
PROVIDERS = provider_api.ProviderAPIs


class Password(base.AuthMethodHandler):

    def authenticate(self, auth_payload):
        """Try to authenticate against the identity backend."""
        response_data = {}
        user_info = auth_plugins.UserAuthInfo.create(auth_payload, METHOD_NAME)

        try:
            PROVIDERS.identity_api.authenticate(
                user_id=user_info.user_id,
                password=user_info.password)
        except AssertionError:
            # authentication failed because of invalid username or password
            msg = _('Invalid username or password')
            raise exception.Unauthorized(msg)

        response_data['user_id'] = user_info.user_id

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)

# Copyright 2018 SUSE Linux GmbH
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


PROVIDERS = provider_api.ProviderAPIs
METHOD_NAME = 'application_credential'


class ApplicationCredential(base.AuthMethodHandler):
    def authenticate(self, auth_payload):
        """Authenticate an application."""
        response_data = {}
        app_cred_info = auth_plugins.AppCredInfo.create(auth_payload,
                                                        METHOD_NAME)

        try:
            PROVIDERS.application_credential_api.authenticate(
                application_credential_id=app_cred_info.id,
                secret=app_cred_info.secret)
        except AssertionError as e:
            raise exception.Unauthorized(e)
        response_data['user_id'] = app_cred_info.user_id

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)

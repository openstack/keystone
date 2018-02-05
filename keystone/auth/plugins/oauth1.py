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

from oslo_utils import timeutils

from keystone.auth.plugins import base
from keystone.common import controller
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _
from keystone.oauth1 import core as oauth
from keystone.oauth1 import validator


PROVIDERS = provider_api.ProviderAPIs


class OAuth(base.AuthMethodHandler):
    def authenticate(self, request, auth_payload):
        """Turn a signed request with an access key into a keystone token."""
        response_data = {}
        oauth_headers = oauth.get_oauth_headers(request.headers)
        access_token_id = oauth_headers.get('oauth_token')

        if not access_token_id:
            raise exception.ValidationError(
                attribute='oauth_token', target='request')

        acc_token = PROVIDERS.oauth_api.get_access_token(access_token_id)

        expires_at = acc_token['expires_at']
        if expires_at:
            now = timeutils.utcnow()
            expires = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
            if now > expires:
                raise exception.Unauthorized(_('Access token is expired'))

        url = controller.V3Controller.base_url(request.context_dict,
                                               request.path_info)
        access_verifier = oauth.ResourceEndpoint(
            request_validator=validator.OAuthValidator(),
            token_generator=oauth.token_generator)
        result, request = access_verifier.validate_protected_resource_request(
            url,
            http_method='POST',
            body=request.params,
            headers=request.headers,
            realms=None
        )
        if not result:
            msg = _('Could not validate the access token')
            raise exception.Unauthorized(msg)
        response_data['user_id'] = acc_token['authorizing_user_id']
        response_data['access_token_id'] = access_token_id
        response_data['project_id'] = acc_token['project_id']

        return base.AuthHandlerResponse(status=True, response_body=None,
                                        response_data=response_data)

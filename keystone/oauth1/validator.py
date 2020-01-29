# Copyright 2014 OpenStack Foundation
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

"""oAuthlib request validator."""

from keystone.common import provider_api
from keystone import exception
from keystone.oauth1.backends import base
from keystone.oauth1 import core as oauth1


METHOD_NAME = 'oauth_validator'
PROVIDERS = provider_api.ProviderAPIs


class OAuthValidator(provider_api.ProviderAPIMixin, oauth1.RequestValidator):

    # TODO(mhu) set as option probably?
    @property
    def enforce_ssl(self):
        return False

    @property
    def safe_characters(self):
        # oauth tokens are generated from a uuid hex value
        return set("abcdef0123456789")

    def _check_token(self, token):
        # generic token verification when they're obtained from a uuid hex
        return (set(token) <= self.safe_characters and
                len(token) == 32)

    def check_client_key(self, client_key):
        return self._check_token(client_key)

    def check_request_token(self, request_token):
        return self._check_token(request_token)

    def check_access_token(self, access_token):
        return self._check_token(access_token)

    def check_nonce(self, nonce):
        # Assuming length is not a concern
        return set(nonce) <= self.safe_characters

    def check_verifier(self, verifier):
        return (all(i in base.VERIFIER_CHARS for i in verifier) and
                len(verifier) == 8)

    def get_client_secret(self, client_key, request):
        client = PROVIDERS.oauth_api.get_consumer_with_secret(client_key)
        return client['secret']

    def get_request_token_secret(self, client_key, token, request):
        token_ref = PROVIDERS.oauth_api.get_request_token(token)
        return token_ref['request_secret']

    def get_access_token_secret(self, client_key, token, request):
        access_token = PROVIDERS.oauth_api.get_access_token(token)
        return access_token['access_secret']

    def get_default_realms(self, client_key, request):
        # realms weren't implemented with the previous library
        return []

    def get_realms(self, token, request):
        return []

    def get_redirect_uri(self, token, request):
        # OOB (out of band) is supposed to be the default value to use
        return 'oob'

    def get_rsa_key(self, client_key, request):
        # HMAC signing is used, so return a dummy value
        return ''

    def invalidate_request_token(self, client_key, request_token, request):
        """Invalidate a used request token.

        :param client_key: The client/consumer key.
        :param request_token: The request token string.
        :param request: An oauthlib.common.Request object.
        :returns: None

        Per `Section 2.3`_ of the spec:

        "The server MUST (...) ensure that the temporary
        credentials have not expired or been used before."

        .. _`Section 2.3`: https://tools.ietf.org/html/rfc5849#section-2.3

        This method should ensure that provided token won't validate anymore.
        It can be simply removing RequestToken from storage or setting
        specific flag that makes it invalid (note that such flag should be
        also validated during request token validation).

        This method is used by

        * AccessTokenEndpoint
        """
        # FIXME(lbragstad): Remove the above documentation string once
        # https://bugs.launchpad.net/keystone/+bug/1778603 is resolved. It is
        # being duplicated here to work around oauthlib compatibility issues
        # with Sphinx 1.7.5, which have been reported upstream in
        # https://github.com/oauthlib/oauthlib/issues/558.

        # this method is invoked when an access token is generated out of a
        # request token, to make sure that request token cannot be consumed
        # anymore. This is done in the backend, so we do nothing here.
        pass

    def validate_client_key(self, client_key, request):
        try:
            return PROVIDERS.oauth_api.get_consumer(client_key) is not None
        except exception.NotFound:
            return False

    def validate_request_token(self, client_key, token, request):
        try:
            req_token = PROVIDERS.oauth_api.get_request_token(token)
            if req_token:
                return req_token['consumer_id'] == client_key
            else:
                return False
        except exception.NotFound:
            return False

    def validate_access_token(self, client_key, token, request):
        try:
            return PROVIDERS.oauth_api.get_access_token(token) is not None
        except exception.NotFound:
            return False

    def validate_timestamp_and_nonce(self,
                                     client_key,
                                     timestamp,
                                     nonce,
                                     request,
                                     request_token=None,
                                     access_token=None):
        return True

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        # we expect OOB, we don't really care
        return True

    def validate_requested_realms(self, client_key, realms, request):
        # realms are not used
        return True

    def validate_realms(self,
                        client_key,
                        token,
                        request,
                        uri=None,
                        realms=None):
        return True

    def validate_verifier(self, client_key, token, verifier, request):
        try:
            req_token = PROVIDERS.oauth_api.get_request_token(token)
            return req_token['verifier'] == verifier
        except exception.NotFound:
            return False

    def verify_request_token(self, token, request):
        # there aren't strong expectations on the request token format
        return isinstance(token, str)

    def verify_realms(self, token, realms, request):
        return True

    # The following save_XXX methods are called to create tokens. I chose to
    # keep the original logic, but the comments below show how that could be
    # implemented. The real implementation logic is in the backend.
    def save_access_token(self, token, request):
        pass
#        token_duration = CONF.oauth1.request_token_duration
#        request_token_id = request.client_key
#        self.oauth_api.create_access_token(request_token_id,
#                                           token_duration,
#                                           token["oauth_token"],
#                                           token["oauth_token_secret"])

    def save_request_token(self, token, request):
        pass
#        project_id = request.headers.get('Requested-Project-Id')
#        token_duration = CONF.oauth1.request_token_duration
#        self.oauth_api.create_request_token(request.client_key,
#                                            project_id,
#                                            token_duration,
#                                            token["oauth_token"],
#                                            token["oauth_token_secret"])

    def save_verifier(self, token, verifier, request):
        """Associate an authorization verifier with a request token.

        :param token: A request token string.
        :param verifier: A dictionary containing the oauth_verifier and
                         oauth_token
        :param request: An oauthlib.common.Request object.

        We need to associate verifiers with tokens for validation during the
        access token request.

        Note that unlike save_x_token token here is the ``oauth_token`` token
        string from the request token saved previously.

        This method is used by

        * AuthorizationEndpoint
        """
        # FIXME(lbragstad): Remove the above documentation string once
        # https://bugs.launchpad.net/keystone/+bug/1778603 is resolved. It is
        # being duplicated here to work around oauthlib compatibility issues
        # with Sphinx 1.7.5, which have been reported upstream in
        # https://github.com/oauthlib/oauthlib/issues/558.

        # keep the old logic for this, as it is done in two steps and requires
        # information that the request validator has no access to
        pass

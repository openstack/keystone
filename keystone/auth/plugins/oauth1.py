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

from keystone import auth
from keystone.common import dependency
from keystone.contrib import oauth1
from keystone.contrib.oauth1 import core as oauth
from keystone import exception
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils


METHOD_NAME = 'oauth1'
LOG = logging.getLogger(__name__)


@dependency.requires('oauth_api')
class OAuth(auth.AuthMethodHandler):
    def __init__(self):
        self.oauth_api = oauth1.Manager()

    def authenticate(self, context, auth_info, auth_context):
        """Turn a signed request with an access key into a keystone token."""
        headers = context['headers']
        oauth_headers = oauth.get_oauth_headers(headers)
        consumer_id = oauth_headers.get('oauth_consumer_key')
        access_token_id = oauth_headers.get('oauth_token')

        if not access_token_id:
            raise exception.ValidationError(
                attribute='oauth_token', target='request')

        acc_token = self.oauth_api.get_access_token(access_token_id)
        consumer = self.oauth_api.get_consumer_with_secret(consumer_id)

        expires_at = acc_token['expires_at']
        if expires_at:
            now = timeutils.utcnow()
            expires = timeutils.normalize_time(
                timeutils.parse_isotime(expires_at))
            if now > expires:
                raise exception.Unauthorized(_('Access token is expired'))

        consumer_obj = oauth1.Consumer(key=consumer['id'],
                                       secret=consumer['secret'])
        acc_token_obj = oauth1.Token(key=acc_token['id'],
                                     secret=acc_token['access_secret'])

        url = oauth.rebuild_url(context['path'])
        oauth_request = oauth1.Request.from_request(
            http_method='POST',
            http_url=url,
            headers=context['headers'],
            query_string=context['query_string'])
        oauth_server = oauth1.Server()
        oauth_server.add_signature_method(oauth1.SignatureMethod_HMAC_SHA1())
        params = oauth_server.verify_request(oauth_request,
                                             consumer_obj,
                                             token=acc_token_obj)

        if len(params) != 0:
            msg = _('There should not be any non-oauth parameters')
            raise exception.Unauthorized(message=msg)

        auth_context['user_id'] = acc_token['authorizing_user_id']
        auth_context['access_token_id'] = access_token_id
        auth_context['project_id'] = acc_token['project_id']

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

from keystone.common import wsgi
from keystone.contrib import oauth1
from keystone.contrib.oauth1 import controllers


class OAuth1Extension(wsgi.V3ExtensionRouter):
    """API Endpoints for the OAuth1 extension.

    The goal of this extension is to allow third-party service providers
    to acquire tokens with a limited subset of a user's roles for acting
    on behalf of that user. This is done using an oauth-similar flow and
    api.

    The API looks like::

      # Basic admin-only consumer crud
      POST /OS-OAUTH1/consumers
      GET /OS-OAUTH1/consumers
      PATCH /OS-OAUTH1/consumers/$consumer_id
      GET /OS-OAUTH1/consumers/$consumer_id
      DELETE /OS-OAUTH1/consumers/$consumer_id

      # User access token crud
      GET /users/$user_id/OS-OAUTH1/access_tokens
      GET /users/$user_id/OS-OAUTH1/access_tokens/$access_token_id
      GET /users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/roles
      GET /users/{user_id}/OS-OAUTH1/access_tokens
          /{access_token_id}/roles/{role_id}
      DELETE /users/$user_id/OS-OAUTH1/access_tokens/$access_token_id

      # OAuth interfaces
      POST /OS-OAUTH1/request_token  # create a request token
      PUT /OS-OAUTH1/authorize  # authorize a request token
      POST /OS-OAUTH1/access_token  # create an access token

    """

    def add_routes(self, mapper):
        # This is needed for dependency injection,
        # it loads the OAuth driver which registers it as a dependency.
        oauth1.Manager()
        consumer_controller = controllers.ConsumerCrudV3()
        access_token_controller = controllers.AccessTokenCrudV3()
        access_token_roles_controller = controllers.AccessTokenRolesV3()
        oauth_controller = controllers.OAuthControllerV3()

        # basic admin-only consumer crud
        self._add_resource(
            mapper, consumer_controller,
            path='/OS-OAUTH1/consumers',
            get_action='list_consumers',
            post_action='create_consumer')
        self._add_resource(
            mapper, consumer_controller,
            path='/OS-OAUTH1/consumers/{consumer_id}',
            get_action='get_consumer',
            patch_action='update_consumer',
            delete_action='delete_consumer')

        # user accesss token crud
        self._add_resource(
            mapper, access_token_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens',
            get_action='list_access_tokens')
        self._add_resource(
            mapper, access_token_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}',
            get_action='get_access_token',
            delete_action='delete_access_token')
        self._add_resource(
            mapper, access_token_roles_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/'
            'roles',
            get_action='list_access_token_roles')
        self._add_resource(
            mapper, access_token_roles_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/'
            'roles/{role_id}',
            get_action='get_access_token_role')

        # oauth flow calls
        self._add_resource(
            mapper, oauth_controller,
            path='/OS-OAUTH1/request_token',
            post_action='create_request_token')
        self._add_resource(
            mapper, oauth_controller,
            path='/OS-OAUTH1/access_token',
            post_action='create_access_token')
        self._add_resource(
            mapper, oauth_controller,
            path='/OS-OAUTH1/authorize/{request_token_id}',
            put_action='authorize_request_token')

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

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib.oauth1 import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-OAUTH1', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-OAUTH1', extension_version='1.0')

ACCESS_TOKEN_ID_PARAMETER_RELATION = build_parameter_relation(
    parameter_name='access_token_id')


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
      PATCH /OS-OAUTH1/consumers/{consumer_id}
      GET /OS-OAUTH1/consumers/{consumer_id}
      DELETE /OS-OAUTH1/consumers/{consumer_id}

      # User access token crud
      GET /users/{user_id}/OS-OAUTH1/access_tokens
      GET /users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}
      GET /users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/roles
      GET /users/{user_id}/OS-OAUTH1/access_tokens
          /{access_token_id}/roles/{role_id}
      DELETE /users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}

      # OAuth interfaces
      POST /OS-OAUTH1/request_token  # create a request token
      PUT /OS-OAUTH1/authorize  # authorize a request token
      POST /OS-OAUTH1/access_token  # create an access token

    """

    def add_routes(self, mapper):
        consumer_controller = controllers.ConsumerCrudV3()
        access_token_controller = controllers.AccessTokenCrudV3()
        access_token_roles_controller = controllers.AccessTokenRolesV3()
        oauth_controller = controllers.OAuthControllerV3()

        # basic admin-only consumer crud
        self._add_resource(
            mapper, consumer_controller,
            path='/OS-OAUTH1/consumers',
            get_action='list_consumers',
            post_action='create_consumer',
            rel=build_resource_relation(resource_name='consumers'))
        self._add_resource(
            mapper, consumer_controller,
            path='/OS-OAUTH1/consumers/{consumer_id}',
            get_action='get_consumer',
            patch_action='update_consumer',
            delete_action='delete_consumer',
            rel=build_resource_relation(resource_name='consumer'),
            path_vars={
                'consumer_id':
                build_parameter_relation(parameter_name='consumer_id'),
            })

        # user access token crud
        self._add_resource(
            mapper, access_token_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens',
            get_action='list_access_tokens',
            rel=build_resource_relation(resource_name='user_access_tokens'),
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, access_token_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}',
            get_action='get_access_token',
            delete_action='delete_access_token',
            rel=build_resource_relation(resource_name='user_access_token'),
            path_vars={
                'access_token_id': ACCESS_TOKEN_ID_PARAMETER_RELATION,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, access_token_roles_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/'
            'roles',
            get_action='list_access_token_roles',
            rel=build_resource_relation(
                resource_name='user_access_token_roles'),
            path_vars={
                'access_token_id': ACCESS_TOKEN_ID_PARAMETER_RELATION,
                'user_id': json_home.Parameters.USER_ID,
            })
        self._add_resource(
            mapper, access_token_roles_controller,
            path='/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}/'
            'roles/{role_id}',
            get_action='get_access_token_role',
            rel=build_resource_relation(
                resource_name='user_access_token_role'),
            path_vars={
                'access_token_id': ACCESS_TOKEN_ID_PARAMETER_RELATION,
                'role_id': json_home.Parameters.ROLE_ID,
                'user_id': json_home.Parameters.USER_ID,
            })

        # oauth flow calls
        self._add_resource(
            mapper, oauth_controller,
            path='/OS-OAUTH1/request_token',
            post_action='create_request_token',
            rel=build_resource_relation(resource_name='request_tokens'))
        self._add_resource(
            mapper, oauth_controller,
            path='/OS-OAUTH1/access_token',
            post_action='create_access_token',
            rel=build_resource_relation(resource_name='access_tokens'))
        self._add_resource(
            mapper, oauth_controller,
            path='/OS-OAUTH1/authorize/{request_token_id}',
            path_vars={
                'request_token_id':
                build_parameter_relation(parameter_name='request_token_id')
            },
            put_action='authorize_request_token',
            rel=build_resource_relation(
                resource_name='authorize_request_token'))

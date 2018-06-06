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
"""WSGI Routers for the Application Credential service."""

from keystone.application_credential import controllers
from keystone.common import json_home
from keystone.common import wsgi

APP_CRED_RESOURCE_RELATION = json_home.build_v3_resource_relation(
    'application_credential')
APP_CRED_PARAMETER_RELATION = json_home.build_v3_parameter_relation(
    'application_credential_id')
APP_CRED_COLLECTION_PATH = '/users/{user_id}/application_credentials'
APP_CRED_RESOURCE_PATH = (
    '/users/{user_id}/application_credentials/{application_credential_id}'
)


class Routers(wsgi.RoutersBase):
    _path_prefixes = (APP_CRED_COLLECTION_PATH, 'users',)

    def append_v3_routers(self, mapper, routers):
        app_cred_controller = controllers.ApplicationCredentialV3()

        self._add_resource(
            mapper, app_cred_controller,
            path=APP_CRED_COLLECTION_PATH,
            get_head_action='list_application_credentials',
            post_action='create_application_credential',
            rel=APP_CRED_RESOURCE_RELATION,
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
            })

        self._add_resource(
            mapper, app_cred_controller,
            path=APP_CRED_RESOURCE_PATH,
            get_head_action='get_application_credential',
            delete_action='delete_application_credential',
            rel=APP_CRED_RESOURCE_RELATION,
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
                'application_credential_id': APP_CRED_PARAMETER_RELATION,
            })

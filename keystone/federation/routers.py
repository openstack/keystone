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
from keystone.federation import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-FEDERATION', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-FEDERATION', extension_version='1.0')

IDP_ID_PARAMETER_RELATION = build_parameter_relation(parameter_name='idp_id')
PROTOCOL_ID_PARAMETER_RELATION = build_parameter_relation(
    parameter_name='protocol_id')
SP_ID_PARAMETER_RELATION = build_parameter_relation(parameter_name='sp_id')


class Routers(wsgi.RoutersBase):
    """API Endpoints for the Federation extension.

    The API looks like::

        GET /auth/OS-FEDERATION/identity_providers/
            {idp_id}/protocols/{protocol_id}/websso
            ?origin=https%3A//horizon.example.com
        POST /auth/OS-FEDERATION/identity_providers/
            {idp_id}/protocols/{protocol_id}/websso
            ?origin=https%3A//horizon.example.com


        POST /auth/OS-FEDERATION/saml2
        POST /auth/OS-FEDERATION/saml2/ecp

        GET /auth/OS-FEDERATION/websso/{protocol_id}
            ?origin=https%3A//horizon.example.com

        POST /auth/OS-FEDERATION/websso/{protocol_id}
             ?origin=https%3A//horizon.example.com

    """

    _path_prefixes = ('auth',)

    def _construct_url(self, suffix):
        return "/OS-FEDERATION/%s" % suffix

    def append_v3_routers(self, mapper, routers):
        auth_controller = controllers.Auth()

        # Auth operations
        self._add_resource(
            mapper, auth_controller,
            path='/auth' + self._construct_url('saml2'),
            post_action='create_saml_assertion',
            rel=build_resource_relation(resource_name='saml2'))
        self._add_resource(
            mapper, auth_controller,
            path='/auth' + self._construct_url('saml2/ecp'),
            post_action='create_ecp_assertion',
            rel=build_resource_relation(resource_name='ecp'))
        self._add_resource(
            mapper, auth_controller,
            path='/auth' + self._construct_url('websso/{protocol_id}'),
            get_post_action='federated_sso_auth',
            rel=build_resource_relation(resource_name='websso'),
            path_vars={
                'protocol_id': PROTOCOL_ID_PARAMETER_RELATION,
            })
        self._add_resource(
            mapper, auth_controller,
            path='/auth' + self._construct_url(
                 'identity_providers/{idp_id}/protocols/{protocol_id}/websso'),
            get_post_action='federated_idp_specific_sso_auth',
            rel=build_resource_relation(
                resource_name='identity_providers_websso'),
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION,
                'protocol_id': PROTOCOL_ID_PARAMETER_RELATION,
            })

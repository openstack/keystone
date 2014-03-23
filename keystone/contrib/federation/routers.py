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
from keystone.contrib import federation
from keystone.contrib.federation import controllers


class FederationExtension(wsgi.ExtensionRouter):
    """API Endpoints for the Federation extension.

    The API looks like::

        PUT /OS-FEDERATION/identity_providers/$identity_provider
        GET /OS-FEDERATION/identity_providers
        GET /OS-FEDERATION/identity_providers/$identity_provider
        DELETE /OS-FEDERATION/identity_providers/$identity_provider
        PATCH /OS-FEDERATION/identity_providers/$identity_provider

        PUT /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol
        GET /OS-FEDERATION/identity_providers/
            $identity_provider/protocols
        GET /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol
        PATCH /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol
        DELETE /OS-FEDERATION/identity_providers/
            $identity_provider/protocols/$protocol

        PUT /OS-FEDERATION/mappings
        GET /OS-FEDERATION/mappings
        PATCH /OS-FEDERATION/mappings/$mapping_id
        GET /OS-FEDERATION/mappings/$mapping_id
        DELETE /OS-FEDERATION/mappings/$mapping_id

        GET /OS-FEDERATION/projects
        GET /OS-FEDERATION/domains

        GET /OS-FEDERATION/identity_providers/$identity_provider/
            protocols/$protocol/auth
        POST /OS-FEDERATION/identity_providers/$identity_provider/
            protocols/$protocol/auth

    """

    def _construct_url(self, suffix):
        return "/OS-FEDERATION/%s" % suffix

    def add_routes(self, mapper):
        # This is needed for dependency injection
        # it loads the Federation driver which registers it as a dependency.
        federation.Manager()
        auth_controller = controllers.Auth()
        idp_controller = controllers.IdentityProvider()
        protocol_controller = controllers.FederationProtocol()
        mapping_controller = controllers.MappingController()
        project_controller = controllers.ProjectV3()
        domain_controller = controllers.DomainV3()

        # Identity Provider CRUD operations

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}'),
            controller=idp_controller,
            action='create_identity_provider',
            conditions=dict(method=['PUT']))

        mapper.connect(
            self._construct_url('identity_providers'),
            controller=idp_controller,
            action='list_identity_providers',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}'),
            controller=idp_controller,
            action='get_identity_provider',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}'),
            controller=idp_controller,
            action='delete_identity_provider',
            conditions=dict(method=['DELETE']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}'),
            controller=idp_controller,
            action='update_identity_provider',
            conditions=dict(method=['PATCH']))

        # Protocol CRUD operations

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}/'
                                'protocols/{protocol_id}'),
            controller=protocol_controller,
            action='create_protocol',
            conditions=dict(method=['PUT']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}/'
                                'protocols/{protocol_id}'),
            controller=protocol_controller,
            action='update_protocol',
            conditions=dict(method=['PATCH']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}/'
                                'protocols/{protocol_id}'),
            controller=protocol_controller,
            action='get_protocol',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}/'
                                'protocols'),
            controller=protocol_controller,
            action='list_protocols',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('identity_providers/{idp_id}/'
                                'protocols/{protocol_id}'),
            controller=protocol_controller,
            action='delete_protocol',
            conditions=dict(method=['DELETE']))

        # Mapping CRUD operations

        mapper.connect(
            self._construct_url('mappings/{mapping_id}'),
            controller=mapping_controller,
            action='create_mapping',
            conditions=dict(method=['PUT']))

        mapper.connect(
            self._construct_url('mappings'),
            controller=mapping_controller,
            action='list_mappings',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('mappings/{mapping_id}'),
            controller=mapping_controller,
            action='get_mapping',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('mappings/{mapping_id}'),
            controller=mapping_controller,
            action='delete_mapping',
            conditions=dict(method=['DELETE']))

        mapper.connect(
            self._construct_url('mappings/{mapping_id}'),
            controller=mapping_controller,
            action='update_mapping',
            conditions=dict(method=['PATCH']))

        mapper.connect(
            self._construct_url('domains'),
            controller=domain_controller,
            action='list_domains_for_groups',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('projects'),
            controller=project_controller,
            action='list_projects_for_groups',
            conditions=dict(method=['GET']))

        mapper.connect(
            self._construct_url('identity_providers/'
                                '{identity_provider}/protocols/'
                                '{protocol}/auth'),
            controller=auth_controller,
            action='federated_authentication',
            conditions=dict(method=['GET', 'POST']))

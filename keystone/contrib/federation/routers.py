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


class _BaseFederationExtension(wsgi.V3ExtensionRouter):
    """Base class for Federation Extension classes.

    All generic methods should be stored here so
    inheriting classes don't need to reimplement them.

    """
    def _construct_url(self, suffix):
        return "/OS-FEDERATION/%s" % suffix


class FederationExtension(_BaseFederationExtension):
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

        self._add_resource(
            mapper, idp_controller,
            path=self._construct_url('identity_providers/{idp_id}'),
            get_action='get_identity_provider',
            put_action='create_identity_provider',
            patch_action='update_identity_provider',
            delete_action='delete_identity_provider')
        self._add_resource(
            mapper, idp_controller,
            path=self._construct_url('identity_providers'),
            get_action='list_identity_providers')

        # Protocol CRUD operations

        self._add_resource(
            mapper, protocol_controller,
            path=self._construct_url('identity_providers/{idp_id}/protocols/'
                                     '{protocol_id}'),
            get_action='get_protocol',
            put_action='create_protocol',
            patch_action='update_protocol',
            delete_action='delete_protocol')
        self._add_resource(
            mapper, protocol_controller,
            path=self._construct_url('identity_providers/{idp_id}/protocols'),
            get_action='list_protocols')

        # Mapping CRUD operations

        self._add_resource(
            mapper, mapping_controller,
            path=self._construct_url('mappings/{mapping_id}'),
            get_action='get_mapping',
            put_action='create_mapping',
            patch_action='update_mapping',
            delete_action='delete_mapping')
        self._add_resource(
            mapper, mapping_controller,
            path=self._construct_url('mappings'),
            get_action='list_mappings')
        self._add_resource(
            mapper, domain_controller,
            path=self._construct_url('domains'),
            get_action='list_domains_for_groups')
        self._add_resource(
            mapper, project_controller,
            path=self._construct_url('projects'),
            get_action='list_projects_for_groups')
        self._add_resource(
            mapper, auth_controller,
            path=self._construct_url('identity_providers/{identity_provider}/'
                                     'protocols/{protocol}/auth'),
            get_post_action='federated_authentication')

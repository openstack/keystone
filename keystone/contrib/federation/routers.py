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

from keystone.common import wsgi
from keystone.contrib.federation import controllers


class FederationExtension(wsgi.ExtensionRouter):
    """API Endpoints for the Federation extension.

    The API looks like::

        PUT /OS-FEDERATION/identity_providers
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

    """

    def _construct_url(self, suffix):
        return "/OS-FEDERATION/%s" % suffix

    def add_routes(self, mapper):
        idp_controller = controllers.IdentityProvider()
        protocol_controller = controllers.FederationProtocol()

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

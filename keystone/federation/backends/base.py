# Copyright 2012 OpenStack Foundation
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

import abc

from keystone import exception


class FederationDriverBase(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_idp(self, idp_id, idp):
        """Create an identity provider.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :param idp: idp object
        :type idp: dict
        :returns: idp ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_idp(self, idp_id):
        """Delete an identity provider.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_idp(self, idp_id):
        """Get an identity provider by ID.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :returns: idp ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_idp_from_remote_id(self, remote_id):
        """Get an identity provider by remote ID.

        :param remote_id: ID of remote IdP
        :type idp_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :returns: idp ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_idp(self, idp_id, idp):
        """Update an identity provider by ID.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :param idp: idp object
        :type idp: dict
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :returns: idp ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_protocol(self, idp_id, protocol_id, protocol):
        """Add an IdP-Protocol configuration.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :param protocol_id: ID of protocol object
        :type protocol_id: string
        :param protocol: protocol object
        :type protocol: dict
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :returns: protocol ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_protocol(self, idp_id, protocol_id, protocol):
        """Change an IdP-Protocol configuration.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :param protocol_id: ID of protocol object
        :type protocol_id: string
        :param protocol: protocol object
        :type protocol: dict
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :raises keystone.exception.FederatedProtocolNotFound: If the federated
            protocol cannot be found.
        :returns: protocol ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_protocol(self, idp_id, protocol_id):
        """Get an IdP-Protocol configuration.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :param protocol_id: ID of protocol object
        :type protocol_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :raises keystone.exception.FederatedProtocolNotFound: If the federated
            protocol cannot be found.
        :returns: protocol ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_protocols(self, idp_id):
        """List an IdP's supported protocols.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :returns: list of protocol ref
        :rtype: list of dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_protocol(self, idp_id, protocol_id):
        """Delete an IdP-Protocol configuration.

        :param idp_id: ID of IdP object
        :type idp_id: string
        :param protocol_id: ID of protocol object
        :type protocol_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :raises keystone.exception.FederatedProtocolNotFound: If the federated
            protocol cannot be found.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_mapping(self, mapping_id, mapping):
        """Create a mapping.

        :param mapping_id: ID of mapping object
        :type mapping_id: string
        :param mapping: mapping ref with mapping name
        :type mapping: dict
        :returns: mapping ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_mapping(self, mapping_id):
        """Delete a mapping.

        :param mapping_id: id of mapping to delete
        :type mapping_ref: string
        :returns: None

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_mapping(self, mapping_id, mapping_ref):
        """Update a mapping.

        :param mapping_id: id of mapping to update
        :type mapping_id: string
        :param mapping_ref: new mapping ref
        :type mapping_ref: dict
        :returns: mapping ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_mappings(self):
        """List all mappings.

        :returns: list of mapping refs
        :rtype: list of dicts

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_mapping(self, mapping_id):
        """Get a mapping, returns the mapping based on mapping_id.

        :param mapping_id: id of mapping to get
        :type mapping_ref: string
        :raises keystone.exception.MappingNotFound: If the mapping cannot
            be found.
        :returns: mapping ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_mapping_from_idp_and_protocol(self, idp_id, protocol_id):
        """Get mapping based on idp_id and protocol_id.

        :param idp_id: id of the identity provider
        :type idp_id: string
        :param protocol_id: id of the protocol
        :type protocol_id: string
        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.
        :raises keystone.exception.FederatedProtocolNotFound: If the federated
            protocol cannot be found.
        :returns: mapping ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_sp(self, sp_id, sp):
        """Create a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string
        :param sp: service provider object
        :type sp: dict

        :returns: service provider ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_sp(self, sp_id):
        """Delete a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string

        :raises keystone.exception.ServiceProviderNotFound: If the service
            provider doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_sp(self, sp_id):
        """Get a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string
        :returns: service provider ref
        :rtype: dict

        :raises keystone.exception.ServiceProviderNotFound: If the service
            provider doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_sp(self, sp_id, sp):
        """Update a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string
        :param sp: service prvider object
        :type sp: dict

        :returns: service provider ref
        :rtype: dict

        :raises keystone.exception.ServiceProviderNotFound: If the service
            provider doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_enabled_service_providers(self):
        """List enabled service providers for Service Catalog.

        Service Provider in a catalog contains three attributes: ``id``,
        ``auth_url``, ``sp_url``, where:

        - id is a unique, user defined identifier for service provider object
        - auth_url is an authentication URL of remote Keystone
        - sp_url a URL accessible at the remote service provider where SAML
          assertion is transmitted.

        :returns: list of dictionaries with enabled service providers
        :rtype: list of dicts

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_idps(self, hints):
        """List all identity providers.

        :param hints: filter hints which the driver should
                      implement if at all possible.
        :returns: list of idp refs
        :rtype: list of dicts

        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_sps(self, hints):
        """List all service providers.

        :param hints: filter hints which the driver should
                      implement if at all possible.
        :returns: List of service provider ref objects
        :rtype: list of dicts

        :raises keystone.exception.ServiceProviderNotFound: If the SP
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

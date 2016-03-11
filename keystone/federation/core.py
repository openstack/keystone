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

"""Main entry point into the Federation service."""

import abc

from oslo_config import cfg
from oslo_log import versionutils
import six

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import exception
from keystone.federation import utils


CONF = cfg.CONF
EXTENSION_DATA = {
    'name': 'OpenStack Federation APIs',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-FEDERATION/v1.0',
    'alias': 'OS-FEDERATION',
    'updated': '2013-12-17T12:00:0-00:00',
    'description': 'OpenStack Identity Providers Mechanism.',
    'links': [{
        'rel': 'describedby',
        'type': 'text/html',
        'href': 'http://specs.openstack.org/openstack/keystone-specs/api/v3/'
                'identity-api-v3-os-federation-ext.html',
    }]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)


@dependency.provider('federation_api')
class Manager(manager.Manager):
    """Default pivot point for the Federation backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.federation'

    def __init__(self):
        super(Manager, self).__init__(CONF.federation.driver)

        # Make sure it is a driver version we support, and if it is a legacy
        # driver, then wrap it.
        if isinstance(self.driver, FederationDriverV8):
            self.driver = V9FederationWrapperForV8Driver(self.driver)
        elif not isinstance(self.driver, FederationDriverV9):
            raise exception.UnsupportedDriverVersion(
                driver=CONF.federation.driver)

    def get_enabled_service_providers(self):
        """List enabled service providers for Service Catalog

        Service Provider in a catalog contains three attributes: ``id``,
        ``auth_url``, ``sp_url``, where:

        - id is a unique, user defined identifier for service provider object
        - auth_url is an authentication URL of remote Keystone
        - sp_url a URL accessible at the remote service provider where SAML
          assertion is transmitted.

        :returns: list of dictionaries with enabled service providers
        :rtype: list of dicts

        """
        def normalize(sp):
            ref = {
                'auth_url': sp.auth_url,
                'id': sp.id,
                'sp_url': sp.sp_url
            }
            return ref

        service_providers = self.driver.get_enabled_service_providers()
        return [normalize(sp) for sp in service_providers]

    def evaluate(self, idp_id, protocol_id, assertion_data):
        mapping = self.get_mapping_from_idp_and_protocol(idp_id, protocol_id)
        rules = mapping['rules']
        rule_processor = utils.RuleProcessor(mapping['id'], rules)
        mapped_properties = rule_processor.process(assertion_data)
        return mapped_properties, mapping['id']


# The FederationDriverBase class is the set of driver methods from earlier
# drivers that we still support, that have not been removed or modified. This
# class is then used to created the augmented V8 and V9 version abstract driver
# classes, without having to duplicate a lot of abstract method signatures.
# If you remove a method from V9, then move the abstract methods from this Base
# class to the V8 class. Do not modify any of the method signatures in the Base
# class - changes should only be made in the V8 and subsequent classes.

@six.add_metaclass(abc.ABCMeta)
class FederationDriverBase(object):

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
        :param sp: service prvider object
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

    def get_enabled_service_providers(self):
        """List enabled service providers for Service Catalog

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


class FederationDriverV8(FederationDriverBase):
    """Removed or redefined methods from V8.

    Move the abstract methods of any methods removed or modified in later
    versions of the driver from FederationDriverBase to here. We maintain this
    so that legacy drivers, which will be a subclass of FederationDriverV8, can
    still reference them.

    """

    @abc.abstractmethod
    def list_idps(self):
        """List all identity providers.

        :returns: list of idp refs
        :rtype: list of dicts

        :raises keystone.exception.IdentityProviderNotFound: If the IdP
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_sps(self):
        """List all service providers.

        :returns: List of service provider ref objects
        :rtype: list of dicts

        """
        raise exception.NotImplemented()  # pragma: no cover


class FederationDriverV9(FederationDriverBase):
    """New or redefined methods from V8.

    Add any new V9 abstract methods (or those with modified signatures) to
    this class.

    """

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


class V9FederationWrapperForV8Driver(FederationDriverV9):
    """Wrapper class to supported a V8 legacy driver.

    In order to support legacy drivers without having to make the manager code
    driver-version aware, we wrap legacy drivers so that they look like the
    latest version. For the various changes made in a new driver, here are the
    actions needed in this wrapper:

    Method removed from new driver - remove the call-through method from this
                                     class, since the manager will no longer be
                                     calling it.
    Method signature (or meaning) changed - wrap the old method in a new
                                            signature here, and munge the input
                                            and output parameters accordingly.
    New method added to new driver - add a method to implement the new
                                     functionality here if possible. If that is
                                     not possible, then return NotImplemented,
                                     since we do not guarantee to support new
                                     functionality with legacy drivers.

    """

    @versionutils.deprecated(
        as_of=versionutils.deprecated.MITAKA,
        what='keystone.federation.FederationDriverV8',
        in_favor_of='keystone.federation.FederationDriverV9',
        remove_in=+2)
    def __init__(self, wrapped_driver):
        self.driver = wrapped_driver

    def create_idp(self, idp_id, idp):
        return self.driver.create_idp(idp_id, idp)

    def delete_idp(self, idp_id):
        self.driver.delete_idp(idp_id)

    # NOTE(davechen): The hints is ignored here to support legacy drivers,
    # but the filters in hints will be remain unsatisfied and V3Controller
    # wrapper will apply these filters at the end. So that the result get
    # returned for list IdP will still be filtered with the legacy drivers.
    def list_idps(self, hints):
        return self.driver.list_idps()

    def get_idp(self, idp_id):
        return self.driver.get_idp(idp_id)

    def get_idp_from_remote_id(self, remote_id):
        return self.driver.get_idp_from_remote_id(remote_id)

    def update_idp(self, idp_id, idp):
        return self.driver.update_idp(idp_id, idp)

    def create_protocol(self, idp_id, protocol_id, protocol):
        return self.driver.create_protocol(idp_id, protocol_id, protocol)

    def update_protocol(self, idp_id, protocol_id, protocol):
        return self.driver.update_protocol(idp_id, protocol_id, protocol)

    def get_protocol(self, idp_id, protocol_id):
        return self.driver.get_protocol(idp_id, protocol_id)

    def list_protocols(self, idp_id):
        return self.driver.list_protocols(idp_id)

    def delete_protocol(self, idp_id, protocol_id):
        self.driver.delete_protocol(idp_id, protocol_id)

    def create_mapping(self, mapping_id, mapping):
        return self.driver.create_mapping(mapping_id, mapping)

    def delete_mapping(self, mapping_id):
        self.driver.delete_mapping(mapping_id)

    def update_mapping(self, mapping_id, mapping_ref):
        return self.driver.update_mapping(mapping_id, mapping_ref)

    def list_mappings(self):
        return self.driver.list_mappings()

    def get_mapping(self, mapping_id):
        return self.driver.get_mapping(mapping_id)

    def get_mapping_from_idp_and_protocol(self, idp_id, protocol_id):
        return self.driver.get_mapping_from_idp_and_protocol(
            idp_id, protocol_id)

    def create_sp(self, sp_id, sp):
        return self.driver.create_sp(sp_id, sp)

    def delete_sp(self, sp_id):
        self.driver.delete_sp(sp_id)

    # NOTE(davechen): The hints is ignored here to support legacy drivers,
    # but the filters in hints will be remain unsatisfied and V3Controller
    # wrapper will apply these filters at the end. So that the result get
    # returned for list SPs will still be filtered with the legacy drivers.
    def list_sps(self, hints):
        return self.driver.list_sps()

    def get_sp(self, sp_id):
        return self.driver.get_sp(sp_id)

    def update_sp(self, sp_id, sp):
        return self.driver.update_sp(sp_id, sp)

    def get_enabled_service_providers(self):
        return self.driver.get_enabled_service_providers()


Driver = manager.create_legacy_driver(FederationDriverV8)

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
from oslo_log import log as logging
import six

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone.contrib.federation import utils
from keystone import exception


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
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
        'href': 'https://github.com/openstack/identity-api'
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

    def get_enabled_service_providers(self):
        """List enabled service providers for Service Catalog

        Service Provider in a catalog contains three attributes: ``id``,
        ``auth_url``, ``sp_url``, where:

        - id is an unique, user defined identifier for service provider object
        - auth_url is a authentication URL of remote Keystone
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
        rule_processor = utils.RuleProcessor(rules)
        mapped_properties = rule_processor.process(assertion_data)
        return mapped_properties, mapping['id']


@six.add_metaclass(abc.ABCMeta)
class FederationDriverV8(object):

    @abc.abstractmethod
    def create_idp(self, idp_id, idp):
        """Create an identity provider.

        :returns: idp_ref

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_idp(self, idp_id):
        """Delete an identity provider.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_idps(self):
        """List all identity providers.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_idp(self, idp_id):
        """Get an identity provider by ID.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_idp_from_remote_id(self, remote_id):
        """Get an identity provider by remote ID.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_idp(self, idp_id, idp):
        """Update an identity provider by ID.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_protocol(self, idp_id, protocol_id, protocol):
        """Add an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_protocol(self, idp_id, protocol_id, protocol):
        """Change an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_protocol(self, idp_id, protocol_id):
        """Get an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_protocols(self, idp_id):
        """List an IdP's supported protocols.

        :raises: keystone.exception.IdentityProviderNotFound,

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_protocol(self, idp_id, protocol_id):
        """Delete an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound,

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_mapping(self, mapping_ref):
        """Create a mapping.

        :param mapping_ref: mapping ref with mapping name
        :type mapping_ref: dict
        :returns: mapping_ref

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
        :returns: mapping_ref

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_mappings(self):
        """List all mappings.

        returns: list of mappings

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_mapping(self, mapping_id):
        """Get a mapping, returns the mapping based
        on mapping_id.

        :param mapping_id: id of mapping to get
        :type mapping_ref: string
        :returns: mapping_ref

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_mapping_from_idp_and_protocol(self, idp_id, protocol_id):
        """Get mapping based on idp_id and protocol_id.

        :param idp_id: id of the identity provider
        :type idp_id: string
        :param protocol_id: id of the protocol
        :type protocol_id: string
        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound,
        :returns: mapping_ref

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_sp(self, sp_id, sp):
        """Create a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string
        :param sp: service prvider object
        :type sp: dict

        :returns: sp_ref
        :rtype: dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_sp(self, sp_id):
        """Delete a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string

        :raises: keystone.exception.ServiceProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_sps(self):
        """List all service providers.

        :returns List of sp_ref objects
        :rtype: list of dicts

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_sp(self, sp_id):
        """Get a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string

        :returns: sp_ref
        :raises: keystone.exception.ServiceProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_sp(self, sp_id, sp):
        """Update a service provider.

        :param sp_id: id of the service provider
        :type sp_id: string
        :param sp: service prvider object
        :type sp: dict

        :returns: sp_ref
        :rtype: dict

        :raises: keystone.exception.ServiceProviderNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    def get_enabled_service_providers(self):
        """List enabled service providers for Service Catalog

        Service Provider in a catalog contains three attributes: ``id``,
        ``auth_url``, ``sp_url``, where:

        - id is an unique, user defined identifier for service provider object
        - auth_url is a authentication URL of remote Keystone
        - sp_url a URL accessible at the remote service provider where SAML
          assertion is transmitted.

        :returns: list of dictionaries with enabled service providers
        :rtype: list of dicts

        """
        raise exception.NotImplemented()  # pragma: no cover


Driver = manager.create_legacy_driver(FederationDriverV8)

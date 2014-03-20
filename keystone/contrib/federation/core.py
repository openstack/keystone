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

"""Extension supporting Federation."""

import abc

import six

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging


CONF = config.CONF
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

FEDERATION = 'OS-FEDERATION'
IDENTITY_PROVIDER = 'OS-FEDERATION:identity_provider'
PROTOCOL = 'OS-FEDERATION:protocol'


@dependency.provider('federation_api')
class Manager(manager.Manager):
    """Default pivot point for the Federation backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """
    def __init__(self):
        super(Manager, self).__init__(CONF.federation.driver)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    def create_idp(self, idp_id, idp):
        """Create an identity provider.

        :returns: idp_ref

        """
        raise exception.NotImplemented()

    def delete_idp(self, idp_id):
        """Delete an identity provider.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()

    def list_idps(self):
        """List all identity providers.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()

    def get_idp(self, idp_id):
        """Get an identity provider by ID.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()

    def update_idp(self, idp_id, idp):
        """Update an identity provider by ID.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()

    def create_protocol(self, idp_id, protocol_id, protocol):
        """Add an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound

        """
        raise exception.NotImplemented()

    def update_protocol(self, idp_id, protocol_id, protocol):
        """Change an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound

        """
        raise exception.NotImplemented()

    def get_protocol(self, idp_id, protocol_id):
        """Get an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound

        """
        raise exception.NotImplemented()

    def list_protocols(self, idp_id):
        """List an IdP's supported protocols.

        :raises: keystone.exception.IdentityProviderNotFound,

        """
        raise exception.NotImplemented()

    def delete_protocol(self, idp_id, protocol_id):
        """Delete an IdP-Protocol configuration.

        :raises: keystone.exception.IdentityProviderNotFound,
                 keystone.exception.FederatedProtocolNotFound,

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_mapping(self, mapping_ref):
        """Create a mapping.

        :param mapping_ref: mapping ref with mapping name
        :type mapping_ref: dict
        :returns: mapping_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_mapping(self, mapping_id):
        """Delete a mapping.

        :param mapping_id: id of mapping to delete
        :type mapping_ref: string
        :returns: None

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_mapping(self, mapping_id, mapping_ref):
        """Update a mapping.

        :param mapping_id: id of mapping to update
        :type mapping_id: string
        :param mapping_ref: new mapping ref
        :type mapping_ref: dict
        :returns: mapping_ref

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_mappings(self):
        """List all mappings.

        returns: list of mappings

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_mapping(self, mapping_id):
        """Get a mapping, returns the mapping based
        on mapping_id.

        :param mapping_id: id of mapping to get
        :type mapping_ref: string
        :returns: mapping_ref

        """
        raise exception.NotImplemented()

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
        raise exception.NotImplemented()

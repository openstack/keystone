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

from oslo_config import cfg
from oslo_log import versionutils

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import exception
from keystone.federation.backends import base
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
        if isinstance(self.driver, base.FederationDriverV8):
            self.driver = base.V9FederationWrapperForV8Driver(self.driver)
        elif not isinstance(self.driver, base.FederationDriverV9):
            raise exception.UnsupportedDriverVersion(
                driver=CONF.federation.driver)

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


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.federation.FederationDriverBase',
    in_favor_of='keystone.federation.backends.base.FederationDriverBase',
    remove_in=+1)
class FederationDriverBase(base.FederationDriverBase):
    pass


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.federation.FederationDriverV8',
    in_favor_of='keystone.federation.backends.base.FederationDriverV8',
    remove_in=+1)
class FederationDriverV8(base.FederationDriverV8):
    pass


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.federation.FederationDriverV9',
    in_favor_of='keystone.federation.backends.base.FederationDriverV9',
    remove_in=+1)
class FederationDriverV9(base.FederationDriverV9):
    pass


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.federation.V9FederationWrapperForV8Driver',
    in_favor_of=(
        'keystone.federation.backends.base.V9FederationWrapperForV8Driver'),
    remove_in=+1)
class V9FederationWrapperForV8Driver(base.V9FederationWrapperForV8Driver):
    pass


Driver = manager.create_legacy_driver(base.FederationDriverV8)

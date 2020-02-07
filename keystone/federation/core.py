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

import uuid

from oslo_log import log

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.federation import utils
from keystone.i18n import _
from keystone import notifications

LOG = log.getLogger(__name__)

# This is a general cache region for service providers.
MEMOIZE = cache.get_memoization_decorator(group='federation')

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class Manager(manager.Manager):
    """Default pivot point for the Federation backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.federation'
    _provides_api = 'federation_api'

    def __init__(self):
        super(Manager, self).__init__(CONF.federation.driver)
        notifications.register_event_callback(
            notifications.ACTIONS.internal, notifications.DOMAIN_DELETED,
            self._cleanup_identity_provider
        )

    def _cleanup_identity_provider(self, service, resource_type, operation,
                                   payload):
        domain_id = payload['resource_info']
        hints = driver_hints.Hints()
        hints.add_filter('domain_id', domain_id)
        idps = self.driver.list_idps(hints=hints)
        for idp in idps:
            try:
                self.delete_idp(idp['id'])
            except exception.IdentityProviderNotFound:
                LOG.debug(('Identity Provider %(idpid)s not found when '
                           'deleting domain contents for %(domainid)s, '
                           'continuing with cleanup.'),
                          {'idpid': idp['id'], 'domainid': domain_id})

    def create_idp(self, idp_id, idp):
        auto_created_domain = False
        if not idp.get('domain_id'):
            idp['domain_id'] = self._create_idp_domain(idp_id)
            auto_created_domain = True
        else:
            self._assert_valid_domain_id(idp['domain_id'])

        try:
            return self.driver.create_idp(idp_id, idp)
        except exception.Conflict:
            # If there is a conflict storing the Identity Provider in the
            # backend, then we need to make sure we clean up the domain we just
            # created for it and raise the Conflict exception afterwards.
            if auto_created_domain:
                self._cleanup_idp_domain(idp['domain_id'])
            raise

    def delete_idp(self, idp_id):
        self.driver.delete_idp(idp_id)
        # NOTE(lbragstad): If an identity provider is removed from the system,
        # then we need to invalidate the token cache. Otherwise it will be
        # possible for federated tokens to be considered valid after a service
        # provider removes a federated identity provider resource.
        reason = (
            'The token cache is being invalidated because identity provider '
            '%(idp_id)s has been deleted. Authorization for federated users '
            'will be recalculated and enforced accordingly the next time '
            'they authenticate or validate a token.' % {'idp_id': idp_id}
        )
        notifications.invalidate_token_cache_notification(reason)

    def _cleanup_idp_domain(self, domain_id):
        domain = {'enabled': False}
        PROVIDERS.resource_api.update_domain(domain_id, domain)
        PROVIDERS.resource_api.delete_domain(domain_id)

    def _create_idp_domain(self, idp_id):
        domain_id = uuid.uuid4().hex
        desc = 'Auto generated federated domain for Identity Provider: '
        desc += idp_id
        domain = {
            'id': domain_id,
            'name': domain_id,
            'description': desc,
            'enabled': True
        }
        PROVIDERS.resource_api.create_domain(domain['id'], domain)
        return domain_id

    def _assert_valid_domain_id(self, domain_id):
        PROVIDERS.resource_api.get_domain(domain_id)

    @MEMOIZE
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

    def create_sp(self, sp_id, service_provider):
        sp_ref = self.driver.create_sp(sp_id, service_provider)
        self.get_enabled_service_providers.invalidate(self)
        return sp_ref

    def delete_sp(self, sp_id):
        self.driver.delete_sp(sp_id)
        self.get_enabled_service_providers.invalidate(self)

    def update_sp(self, sp_id, service_provider):
        sp_ref = self.driver.update_sp(sp_id, service_provider)
        self.get_enabled_service_providers.invalidate(self)
        return sp_ref

    def evaluate(self, idp_id, protocol_id, assertion_data):
        mapping = self.get_mapping_from_idp_and_protocol(idp_id, protocol_id)
        rules = mapping['rules']
        rule_processor = utils.RuleProcessor(mapping['id'], rules)
        mapped_properties = rule_processor.process(assertion_data)
        return mapped_properties, mapping['id']

    def create_protocol(self, idp_id, protocol_id, protocol):
        self._validate_mapping_exists(protocol['mapping_id'])
        return self.driver.create_protocol(idp_id, protocol_id, protocol)

    def delete_protocol(self, idp_id, protocol_id):
        hints = driver_hints.Hints()
        hints.add_filter('protocol_id', protocol_id)
        shadow_users = PROVIDERS.shadow_users_api.list_federated_users_info(
            hints)

        self.driver.delete_protocol(idp_id, protocol_id)

        for shadow_user in shadow_users:
            PROVIDERS.identity_api._shadow_federated_user.invalidate(
                PROVIDERS.identity_api, shadow_user['idp_id'],
                shadow_user['protocol_id'], shadow_user['unique_id'],
                shadow_user['display_name'],
                shadow_user.get('extra', {}).get('email'))

    def update_protocol(self, idp_id, protocol_id, protocol):
        self._validate_mapping_exists(protocol['mapping_id'])
        return self.driver.update_protocol(idp_id, protocol_id, protocol)

    def _validate_mapping_exists(self, mapping_id):
        try:
            self.driver.get_mapping(mapping_id)
        except exception.MappingNotFound:
            msg = _('Invalid mapping id: %s')
            raise exception.ValidationError(message=(msg % mapping_id))

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

"""Main entry point into the Trust service."""

from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone import notifications


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class Manager(manager.Manager):
    """Default pivot point for the Trust backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.trust'
    _provides_api = 'trust_api'

    _TRUST = "OS-TRUST:trust"

    def __init__(self):
        super(Manager, self).__init__(CONF.trust.driver)
        notifications.register_event_callback(
            notifications.ACTIONS.deleted, 'user',
            self._on_user_delete)

    def _on_user_delete(self, service, resource_type, operation,
                        payload):
        # NOTE(davechen): Only delete the user that is maintained by
        # keystone will delete the related trust, since we don't know
        # when a LDAP user or federation user is deleted.
        user_id = payload['resource_info']
        trusts = self.driver.list_trusts_for_trustee(user_id)
        trusts = trusts + self.driver.list_trusts_for_trustor(user_id)
        for trust in trusts:
            self.driver.delete_trust(trust['id'])

    @staticmethod
    def _validate_redelegation(redelegated_trust, trust):
        # Validate against:
        # 0 < redelegation_count <= max_redelegation_count
        max_redelegation_count = CONF.trust.max_redelegation_count
        redelegation_depth = redelegated_trust.get('redelegation_count', 0)
        if not (0 < redelegation_depth <= max_redelegation_count):
            raise exception.Forbidden(
                _('Remaining redelegation depth of %(redelegation_depth)d'
                  ' out of allowed range of [0..%(max_count)d]') %
                {'redelegation_depth': redelegation_depth,
                 'max_count': max_redelegation_count})

        # remaining_uses is None
        remaining_uses = trust.get('remaining_uses')
        if remaining_uses is not None:
            raise exception.Forbidden(
                _('Field "remaining_uses" is set to %(value)s'
                  ' while it must not be set in order to redelegate a trust'),
                value=remaining_uses)

        # expiry times
        trust_expiry = trust.get('expires_at')
        redelegated_expiry = redelegated_trust['expires_at']
        if trust_expiry:
            # redelegated trust is from backend and has no tzinfo
            if redelegated_expiry < trust_expiry.replace(tzinfo=None):
                raise exception.Forbidden(
                    _('Requested expiration time is more '
                      'than redelegated trust can provide'))
        else:
            trust['expires_at'] = redelegated_expiry

        # trust roles is a subset of roles of the redelegated trust
        parent_roles = set(role['id']
                           for role in redelegated_trust['roles'])
        if not all(role['id'] in parent_roles for role in trust['roles']):
            raise exception.Forbidden(
                _('Some of requested roles are not in redelegated trust'))

        # forbid to create a trust (with impersonation set to true) from a
        # redelegated trust (with impersonation set to false)
        if not redelegated_trust['impersonation'] and trust['impersonation']:
            raise exception.Forbidden(
                _('Impersonation is not allowed because redelegated trust '
                  'does not specify impersonation. Redelegated trust id: %s') %
                redelegated_trust['id'])

    def get_trust_pedigree(self, trust_id):
        trust = self.driver.get_trust(trust_id)
        trust_chain = [trust]
        while trust and trust.get('redelegated_trust_id'):
            trust = self.driver.get_trust(trust['redelegated_trust_id'])
            trust_chain.append(trust)

        return trust_chain

    def get_trust(self, trust_id, deleted=False):
        trust = self.driver.get_trust(trust_id, deleted)

        if trust and trust.get('redelegated_trust_id') and not deleted:
            trust_chain = self.get_trust_pedigree(trust_id)

            for parent, child in zip(trust_chain[1:], trust_chain):
                self._validate_redelegation(parent, child)
                try:
                    PROVIDERS.identity_api.assert_user_enabled(
                        parent['trustee_user_id'])
                except (AssertionError, exception.NotFound):
                    raise exception.Forbidden(
                        _('One of the trust agents is disabled or deleted'))

        return trust

    def create_trust(self, trust_id, trust, roles, redelegated_trust=None,
                     initiator=None):
        """Create a new trust.

        :returns: a new trust
        """
        # Default for initial trust in chain is max_redelegation_count
        max_redelegation_count = CONF.trust.max_redelegation_count
        requested_count = trust.get('redelegation_count')
        redelegatable = (trust.pop('allow_redelegation', False)
                         and requested_count != 0)
        if not redelegatable:
            trust['redelegation_count'] = requested_count = 0
            remaining_uses = trust.get('remaining_uses')
            if remaining_uses is not None and remaining_uses <= 0:
                msg = _('remaining_uses must be a positive integer or null.')
                raise exception.ValidationError(msg)
        else:
            # Validate requested redelegation depth
            if requested_count and requested_count > max_redelegation_count:
                raise exception.Forbidden(
                    _('Requested redelegation depth of %(requested_count)d '
                      'is greater than allowed %(max_count)d') %
                    {'requested_count': requested_count,
                     'max_count': max_redelegation_count})
            # Decline remaining_uses
            if trust.get('remaining_uses') is not None:
                raise exception.ValidationError(
                    _('remaining_uses must not be set if redelegation is '
                      'allowed'))

        if redelegated_trust:
            trust['redelegated_trust_id'] = redelegated_trust['id']
            remaining_count = redelegated_trust['redelegation_count'] - 1

            # Validate depth consistency
            if (redelegatable and requested_count and
                    requested_count != remaining_count):
                msg = _('Modifying "redelegation_count" upon redelegation is '
                        'forbidden. Omitting this parameter is advised.')
                raise exception.Forbidden(msg)
            trust.setdefault('redelegation_count', remaining_count)

            # Check entire trust pedigree validity
            pedigree = self.get_trust_pedigree(redelegated_trust['id'])
            for t in pedigree:
                self._validate_redelegation(t, trust)

        trust.setdefault('redelegation_count', max_redelegation_count)
        ref = self.driver.create_trust(trust_id, trust, roles)

        notifications.Audit.created(self._TRUST, trust_id, initiator=initiator)

        return ref

    def delete_trust(self, trust_id, initiator=None):
        """Remove a trust.

        :raises keystone.exception.TrustNotFound: If the trust doesn't exist.

        Recursively remove given and redelegated trusts
        """
        trust = self.driver.get_trust(trust_id)
        trusts = self.driver.list_trusts_for_trustor(
            trust['trustor_user_id'],
            redelegated_trust_id=trust_id)

        for t in trusts:
            # recursive call to make sure all notifications are sent
            try:
                self.delete_trust(t['id'])
            except exception.TrustNotFound:  # nosec
                # if trust was deleted by concurrent process
                # consistency must not suffer
                pass

        # end recursion
        self.driver.delete_trust(trust_id)

        notifications.Audit.deleted(self._TRUST, trust_id, initiator)

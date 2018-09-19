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

"""Main entry point into the Revoke service."""

from keystone.common import cache
from keystone.common import manager
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.models import revoke_model
from keystone import notifications


CONF = keystone.conf.CONF

# This builds a discrete cache region dedicated to revoke events. The API can
# return a filtered list based upon last fetchtime. This is deprecated but
# must be maintained.
REVOKE_REGION = cache.create_region(name='revoke')
MEMOIZE = cache.get_memoization_decorator(
    group='revoke',
    region=REVOKE_REGION)


class Manager(manager.Manager):
    """Default pivot point for the Revoke backend.

    Performs common logic for recording revocations.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    driver_namespace = 'keystone.revoke'
    _provides_api = 'revoke_api'

    def __init__(self):
        super(Manager, self).__init__(CONF.revoke.driver)
        self._register_listeners()
        self.model = revoke_model

    @MEMOIZE
    def _list_events(self, last_fetch):
        return self.driver.list_events(last_fetch)

    def list_events(self, last_fetch=None):
        return self._list_events(last_fetch)

    def _user_callback(self, service, resource_type, operation,
                       payload):
        self.revoke_by_user(payload['resource_info'])

    def _project_callback(self, service, resource_type, operation,
                          payload):
        self.revoke(
            revoke_model.RevokeEvent(project_id=payload['resource_info']))

    def _trust_callback(self, service, resource_type, operation,
                        payload):
        self.revoke(
            revoke_model.RevokeEvent(trust_id=payload['resource_info']))

    def _consumer_callback(self, service, resource_type, operation,
                           payload):
        self.revoke(
            revoke_model.RevokeEvent(consumer_id=payload['resource_info']))

    def _register_listeners(self):
        callbacks = {
            notifications.ACTIONS.deleted: [
                ['OS-TRUST:trust', self._trust_callback],
                ['OS-OAUTH1:consumer', self._consumer_callback],
                ['user', self._user_callback],
                ['project', self._project_callback],
            ],
            notifications.ACTIONS.disabled: [
                ['user', self._user_callback]
            ],
            notifications.ACTIONS.internal: [
                [notifications.PERSIST_REVOCATION_EVENT_FOR_USER,
                 self._user_callback],
            ]
        }

        for event, cb_info in callbacks.items():
            for resource_type, callback_fns in cb_info:
                notifications.register_event_callback(event, resource_type,
                                                      callback_fns)

    def revoke_by_user(self, user_id):
        return self.revoke(revoke_model.RevokeEvent(user_id=user_id))

    def _assert_not_domain_and_project_scoped(self, domain_id=None,
                                              project_id=None):
        if domain_id is not None and project_id is not None:
            msg = _('The revoke call must not have both domain_id and '
                    'project_id. This is a bug in the Keystone server. The '
                    'current request is aborted.')
            raise exception.UnexpectedError(exception=msg)

    def revoke_by_audit_id(self, audit_id):
        self.revoke(revoke_model.RevokeEvent(audit_id=audit_id))

    def revoke_by_audit_chain_id(self, audit_chain_id, project_id=None,
                                 domain_id=None):

        self._assert_not_domain_and_project_scoped(domain_id=domain_id,
                                                   project_id=project_id)

        self.revoke(revoke_model.RevokeEvent(audit_chain_id=audit_chain_id,
                                             domain_id=domain_id,
                                             project_id=project_id))

    def check_token(self, token):
        """Check the values from a token against the revocation list.

        :param token: dictionary of values from a token, normalized for
                             differences between v2 and v3. The checked values
                             are a subset of the attributes of model.TokenEvent

        :raises keystone.exception.TokenNotFound: If the token is invalid.

        """
        if revoke_model.is_revoked(self.driver.list_events(token=token),
                                   token):
            raise exception.TokenNotFound(_('Failed to validate token'))

    def revoke(self, event):
        self.driver.revoke(event)
        REVOKE_REGION.invalidate()

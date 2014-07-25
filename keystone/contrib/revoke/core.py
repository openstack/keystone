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
import datetime

import six

from keystone.common import cache
from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import config
from keystone.contrib.revoke import model
from keystone import exception
from keystone import notifications
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log
from keystone.openstack.common import timeutils


CONF = config.CONF
LOG = log.getLogger(__name__)


EXTENSION_DATA = {
    'name': 'OpenStack Revoke API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-REVOKE/v1.0',
    'alias': 'OS-REVOKE',
    'updated': '2014-02-24T20:51:0-00:00',
    'description': 'OpenStack revoked token reporting mechanism.',
    'links': [
        {
            'rel': 'describedby',
            'type': 'text/html',
            'href': ('https://github.com/openstack/identity-api/blob/master/'
                     'openstack-identity-api/v3/src/markdown/'
                     'identity-api-v3-os-revoke-ext.md'),
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)

SHOULD_CACHE = cache.should_cache_fn('revoke')
# TODO(ayoung): migrate from the token section
REVOCATION_CACHE_EXPIRATION_TIME = lambda: CONF.token.revocation_cache_time


def revoked_before_cutoff_time():
    expire_delta = datetime.timedelta(
        seconds=CONF.token.expiration + CONF.revoke.expiration_buffer)
    oldest = timeutils.utcnow() - expire_delta
    return oldest


@dependency.provider('revoke_api')
class Manager(manager.Manager):
    """Revoke API Manager.

    Performs common logic for recording revocations.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.revoke.driver)
        self._register_listeners()
        self.model = model

    def _user_callback(self, service, resource_type, operation,
                       payload):
        self.revoke_by_user(payload['resource_info'])

    def _role_callback(self, service, resource_type, operation,
                       payload):
        self.revoke(
            model.RevokeEvent(role_id=payload['resource_info']))

    def _project_callback(self, service, resource_type, operation,
                          payload):
        self.revoke(
            model.RevokeEvent(project_id=payload['resource_info']))

    def _domain_callback(self, service, resource_type, operation,
                         payload):
        self.revoke(
            model.RevokeEvent(domain_id=payload['resource_info']))

    def _trust_callback(self, service, resource_type, operation,
                        payload):
        self.revoke(
            model.RevokeEvent(trust_id=payload['resource_info']))

    def _consumer_callback(self, service, resource_type, operation,
                           payload):
        self.revoke(
            model.RevokeEvent(consumer_id=payload['resource_info']))

    def _access_token_callback(self, service, resource_type, operation,
                               payload):
        self.revoke(
            model.RevokeEvent(access_token_id=payload['resource_info']))

    def _register_listeners(self):
        callbacks = [
            ['deleted', 'OS-TRUST:trust', self._trust_callback],
            ['deleted', 'OS-OAUTH1:consumer', self._consumer_callback],
            ['deleted', 'OS-OAUTH1:access_token',
             self._access_token_callback],
            ['deleted', 'role', self._role_callback],
            ['deleted', 'user', self._user_callback],
            ['disabled', 'user', self._user_callback],
            ['deleted', 'project', self._project_callback],
            ['disabled', 'project', self._project_callback],
            ['disabled', 'domain', self._domain_callback]]
        for cb in callbacks:
            notifications.register_event_callback(*cb)

    def revoke_by_user(self, user_id):
        return self.revoke(model.RevokeEvent(user_id=user_id))

    def revoke_by_expiration(self, user_id, expires_at,
                             domain_id=None, project_id=None):

        if domain_id is not None and project_id is not None:
            msg = _('The call to keystone.contrib.revoke.Manager '
                    'revoke_by_expiration() must not have both domain_id and '
                    'project_id. This is a bug in the keystone server. The '
                    'current request is aborted.')
            raise exception.UnexpectedError(exception=msg)

        self.revoke(
            model.RevokeEvent(user_id=user_id,
                              expires_at=expires_at,
                              domain_id=domain_id,
                              project_id=project_id))

    def revoke_by_grant(self, role_id, user_id=None,
                        domain_id=None, project_id=None):
        self.revoke(
            model.RevokeEvent(user_id=user_id,
                              role_id=role_id,
                              domain_id=domain_id,
                              project_id=project_id))

    def revoke_by_user_and_project(self, user_id, project_id):
        self.revoke(
            model.RevokeEvent(project_id=project_id, user_id=user_id))

    def revoke_by_project_role_assignment(self, project_id, role_id):
        self.revoke(model.RevokeEvent(project_id=project_id, role_id=role_id))

    def revoke_by_domain_role_assignment(self, domain_id, role_id):
        self.revoke(model.RevokeEvent(domain_id=domain_id, role_id=role_id))

    @cache.on_arguments(should_cache_fn=SHOULD_CACHE,
                        expiration_time=REVOCATION_CACHE_EXPIRATION_TIME)
    def _get_revoke_tree(self):
        events = self.driver.get_events()
        revoke_tree = model.RevokeTree(revoke_events=events)

        return revoke_tree

    def check_token(self, token_values):
        """Checks the values from a token against the revocation list

        :param  token_values: dictionary of values from a token,
         normalized for differences between v2 and v3. The checked values are a
         subset of the attributes of model.TokenEvent

        :raises exception.TokenNotFound: if the token is invalid

         """
        if self._get_revoke_tree().is_revoked(token_values):
            raise exception.TokenNotFound(_('Failed to validate token'))

    def revoke(self, event):
        self.driver.revoke(event)
        self._get_revoke_tree.invalidate(self)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface for recording and reporting revocation events."""

    @abc.abstractmethod
    def get_events(self, last_fetch=None):
        """return the revocation events, as a list of objects

        :param last_fetch:   Time of last fetch.  Return all events newer.
        :returns: A list of keystone.contrib.revoke.model.RevokeEvent
                  newer than `last_fetch.`
                  If no last_fetch is specified, returns all events
                  for tokens issued after the expiration cutoff.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def revoke(self, event):
        """register a revocation event

        :param event: An instance of
            keystone.contrib.revoke.model.RevocationEvent

        """
        raise exception.NotImplemented()

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

"""Main entry point into the Credential service."""

import json

from keystone.common import cache
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone import notifications


CONF = keystone.conf.CONF
MEMOIZE = cache.get_memoization_decorator(group='credential')
PROVIDERS = provider_api.ProviderAPIs


class Manager(manager.Manager):
    """Default pivot point for the Credential backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.credential'
    _provides_api = 'credential_api'

    _CRED = 'credential'

    def __init__(self):
        super(Manager, self).__init__(CONF.credential.driver)

    def _decrypt_credential(self, credential):
        """Return a decrypted credential reference."""
        if credential['type'] == 'ec2':
            decrypted_blob = json.loads(
                PROVIDERS.credential_provider_api.decrypt(
                    credential['encrypted_blob'],
                )
            )
        else:
            decrypted_blob = PROVIDERS.credential_provider_api.decrypt(
                credential['encrypted_blob']
            )
        credential['blob'] = decrypted_blob
        credential.pop('key_hash', None)
        credential.pop('encrypted_blob', None)
        return credential

    def _encrypt_credential(self, credential):
        """Return an encrypted credential reference."""
        credential_copy = credential.copy()
        if credential.get('type', None) == 'ec2':
            # NOTE(lbragstad): When dealing with ec2 credentials, it's possible
            # for the `blob` to be a dictionary. Let's make sure we are
            # encrypting a string otherwise encryption will fail.
            encrypted_blob, key_hash = (
                PROVIDERS.credential_provider_api.encrypt(
                    json.dumps(credential['blob'])
                )
            )
        else:
            encrypted_blob, key_hash = (
                PROVIDERS.credential_provider_api.encrypt(
                    credential['blob']
                )
            )
        credential_copy['encrypted_blob'] = encrypted_blob
        credential_copy['key_hash'] = key_hash
        credential_copy.pop('blob', None)
        return credential_copy

    def _assert_limit_not_exceeded(self, user_id):
        user_limit = CONF.credential.user_limit
        if user_limit >= 0:
            cred_count = len(self.list_credentials_for_user(user_id))
            if cred_count >= user_limit:
                raise exception.CredentialLimitExceeded(
                    limit=user_limit)

    @manager.response_truncated
    def list_credentials(self, hints=None):
        credentials = self.driver.list_credentials(
            hints or driver_hints.Hints()
        )
        for credential in credentials:
            credential = self._decrypt_credential(credential)
        return credentials

    def list_credentials_for_user(self, user_id, type=None):
        credentials = self._list_credentials_for_user(user_id, type)
        for credential in credentials:
            credential = self._decrypt_credential(credential)
        return credentials

    @MEMOIZE
    def _list_credentials_for_user(self, user_id, type):
        """List credentials for a specific user."""
        return self.driver.list_credentials_for_user(user_id, type)

    def get_credential(self, credential_id):
        """Return a credential reference."""
        credential = self._get_credential(credential_id)
        return self._decrypt_credential(credential)

    @MEMOIZE
    def _get_credential(self, credential_id):
        return self.driver.get_credential(credential_id)

    def create_credential(self, credential_id, credential,
                          initiator=None):
        """Create a credential."""
        credential_copy = self._encrypt_credential(credential)
        user_id = credential_copy['user_id']
        self._assert_limit_not_exceeded(user_id)
        ref = self.driver.create_credential(credential_id, credential_copy)
        if MEMOIZE.should_cache(ref):
            self._get_credential.set(ref,
                                     credential_copy,
                                     credential_id)
            self._list_credentials_for_user.invalidate(self,
                                                       ref['user_id'],
                                                       ref['type'])
            self._list_credentials_for_user.invalidate(self,
                                                       ref['user_id'],
                                                       None)
        ref.pop('key_hash', None)
        ref.pop('encrypted_blob', None)
        ref['blob'] = credential['blob']
        notifications.Audit.created(
            self._CRED,
            credential_id,
            initiator)
        return ref

    def _validate_credential_update(self, credential_id, credential):
        # ec2 credentials require a "project_id" to be functional. Before we
        # update, check the case where a non-ec2 credential changes its type
        # to be "ec2", but has no associated "project_id", either in the
        # request or already set in the database
        if (credential.get('type', '').lower() == 'ec2' and
                not credential.get('project_id')):
            existing_cred = self.get_credential(credential_id)
            if not existing_cred['project_id']:
                raise exception.ValidationError(attribute='project_id',
                                                target='credential')

    def update_credential(self, credential_id, credential):
        """Update an existing credential."""
        self._validate_credential_update(credential_id, credential)
        if 'blob' in credential:
            credential_copy = self._encrypt_credential(credential)
        else:
            credential_copy = credential.copy()
            existing_credential = self.get_credential(credential_id)
            existing_blob = existing_credential['blob']
        ref = self.driver.update_credential(credential_id, credential_copy)
        if MEMOIZE.should_cache(ref):
            self._get_credential.set(ref, self, credential_id)
            self._list_credentials_for_user.invalidate(self,
                                                       ref['user_id'],
                                                       ref['type'])
            self._list_credentials_for_user.invalidate(self,
                                                       ref['user_id'],
                                                       None)
        ref.pop('key_hash', None)
        ref.pop('encrypted_blob', None)
        # If the update request contains a `blob` attribute - we should return
        # that in the update response. If not, then we should return the
        # existing `blob` attribute since it wasn't updated.
        if credential.get('blob'):
            ref['blob'] = credential['blob']
        else:
            ref['blob'] = existing_blob
        return ref

    def delete_credential(self, credential_id,
                          initiator=None):
        """Delete a credential."""
        cred = self.get_credential(credential_id)
        self.driver.delete_credential(credential_id)
        self._get_credential.invalidate(self, credential_id)
        self._list_credentials_for_user.invalidate(self,
                                                   cred['user_id'],
                                                   cred['type'])
        self._list_credentials_for_user.invalidate(self,
                                                   cred['user_id'],
                                                   None)
        notifications.Audit.deleted(
            self._CRED, credential_id, initiator)

    def delete_credentials_for_project(self, project_id):
        """Delete all credentials for a project."""
        hints = driver_hints.Hints()
        hints.add_filter('project_id', project_id)
        creds = self.driver.list_credentials(hints)

        self.driver.delete_credentials_for_project(project_id)
        for cred in creds:
            self._get_credential.invalidate(self, cred['id'])
            self._list_credentials_for_user.invalidate(self,
                                                       cred['user_id'],
                                                       cred['type'])
            self._list_credentials_for_user.invalidate(self,
                                                       cred['user_id'],
                                                       None)

    def delete_credentials_for_user(self, user_id):
        """Delete all credentials for a user."""
        creds = self.driver.list_credentials_for_user(user_id)
        self.driver.delete_credentials_for_user(user_id)
        for cred in creds:
            self._get_credential.invalidate(self, cred['id'])
            self._list_credentials_for_user.invalidate(self,
                                                       user_id,
                                                       cred['type'])
            self._list_credentials_for_user.invalidate(self,
                                                       cred['user_id'],
                                                       None)

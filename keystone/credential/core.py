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

from oslo_log import versionutils

from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
import keystone.conf
from keystone.credential.backends import base
from keystone import exception


CONF = keystone.conf.CONF


@dependency.provider('credential_api')
class Manager(manager.Manager):
    """Default pivot point for the Credential backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.credential'

    def __init__(self):
        super(Manager, self).__init__(CONF.credential.driver)

    @manager.response_truncated
    def list_credentials(self, hints=None):
        return self.driver.list_credentials(hints or driver_hints.Hints())

    def get_credential(self, credential_id):
        """Return a credential reference."""
        return self.driver.get_credential(credential_id)

    def create_credential(self, credential_id, credential):
        """Create a credential."""
        return self.driver.create_credential(credential_id, credential)

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
        return self.driver.update_credential(credential_id, credential)


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.credential.CredentialDriverV8',
    in_favor_of='keystone.credential.backends.base.CredentialDriverV8',
    remove_in=+1)
class AuthMethodHandler(base.CredentialDriverV8):
    pass


Driver = manager.create_legacy_driver(base.CredentialDriverV8)

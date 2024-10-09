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

import uuid

from oslo_log import log

from keystone.common import provider_api
from keystone.common.validation import validators
import keystone.conf
from keystone import exception
from keystone.identity.mapping_backends import mapping
from keystone import notifications
from keystone.server import backends

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class Identity:
    def __init__(self):
        backends.load_backends()

        self.user_id = None
        self.user_name = None
        self.user_password = None

        self.project_id = None
        self.project_name = None

        self.default_domain_id = CONF.identity.default_domain_id

    def project_setup(self):
        try:
            project_id = self.project_id
            if project_id is None:
                project_id = uuid.uuid4().hex
            project = {
                'enabled': True,
                'id': project_id,
                'domain_id': self.default_domain_id,
                'description': 'Bootstrap project for initializing the cloud.',
                'name': self.project_name,
            }
            PROVIDERS.resource_api.create_project(project_id, project)
            LOG.info('Created project %s', self.project_name)
        except exception.Conflict:
            LOG.info(
                'Project %s already exists, skipping creation.',
                self.project_name,
            )
            project = PROVIDERS.resource_api.get_project_by_name(
                self.project_name, self.default_domain_id
            )

        self.project_id = project['id']

    def _create_user(self, user_ref, initiator=None):
        _self = PROVIDERS.identity_api.create_user.__self__
        user = user_ref.copy()
        if 'password' in user:
            validators.validate_password(user['password'])
        user['name'] = user['name'].strip()
        user.setdefault('enabled', True)
        domain_id = user['domain_id']
        PROVIDERS.resource_api.get_domain(domain_id)

        _self._assert_default_project_id_is_not_domain(
            user_ref.get('default_project_id')
        )

        # For creating a user, the domain is in the object itself
        domain_id = user_ref['domain_id']
        driver = _self._select_identity_driver(domain_id)
        user = _self._clear_domain_id_if_domain_unaware(driver, user)
        # Generate a local ID - in the future this might become a function of
        # the underlying driver so that it could conform to rules set down by
        # that particular driver type.
        user['id'] = self.user_id
        ref = _self._create_user_with_federated_objects(user, driver)
        notifications.Audit.created(_self._USER, user['id'], initiator)
        return _self._set_domain_id_and_mapping(
            ref, domain_id, driver, mapping.EntityType.USER
        )

    def user_setup(self):
        # NOTE(morganfainberg): Do not create the user if it already exists.
        try:
            user = PROVIDERS.identity_api.get_user_by_name(
                self.user_name, self.default_domain_id
            )
            LOG.info(
                'User %s already exists, skipping creation.', self.user_name
            )

            if self.user_id is not None and user['id'] != self.user_id:
                msg = (
                    f'user `{self.user_name}` already exists '
                    f'with `{self.user_id}`'
                )
                raise exception.Conflict(type='user_id', details=msg)

            # If the user is not enabled, re-enable them. This also helps
            # provide some useful logging output later.
            update = {}
            enabled = user['enabled']
            if not enabled:
                update['enabled'] = True

            try:
                PROVIDERS.identity_api.driver.authenticate(
                    user['id'], self.user_password
                )
            except AssertionError:
                # This means that authentication failed and that we need to
                # update the user's password. This is going to persist a
                # revocation event that will make all previous tokens for the
                # user invalid, which is OK because it falls within the scope
                # of revocation. If a password changes, we shouldn't be able to
                # use tokens obtained with an old password.
                update['password'] = self.user_password

            # Only make a call to update the user if the password has changed
            # or the user was previously disabled. This allows bootstrap to act
            # as a recovery tool, without having to create a new user.
            if update:
                user = PROVIDERS.identity_api.update_user(user['id'], update)
                LOG.info('Reset password for user %s.', self.user_name)
                if not enabled and user['enabled']:
                    # Although we always try to enable the user, this log
                    # message only makes sense if we know that the user was
                    # previously disabled.
                    LOG.info('Enabled user %s.', self.user_name)
        except exception.UserNotFound:
            user = self._create_user(
                user_ref={
                    'name': self.user_name,
                    'enabled': True,
                    'domain_id': self.default_domain_id,
                    'password': self.user_password,
                }
            )
            LOG.info('Created user %s', self.user_name)

        self.user_id = user['id']

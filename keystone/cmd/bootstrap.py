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

from keystone.common import driver_hints
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.server import backends

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class Bootstrapper(object):

    def __init__(self):
        backends.load_backends()

        self.admin_password = None
        self.admin_username = None

        self.project_id = None
        self.project_name = None

        self.reader_role_id = None
        self.reader_role_name = 'reader'

        self.member_role_id = None
        self.member_role_name = 'member'

        self.admin_role_id = None
        self.admin_role_name = None

        self.region_id = None

        self.service_name = None
        self.public_url = None
        self.internal_url = None
        self.admin_url = None
        self.endpoints = {}

        self.default_domain_id = None
        self.admin_user_id = None

        self.immutable_roles = False

    def bootstrap(self):
        # NOTE(morganfainberg): Ensure the default domain is in-fact created
        self._bootstrap_default_domain()
        self._bootstrap_project()
        self._bootstrap_admin_user()
        self._bootstrap_reader_role()
        self._bootstrap_member_role()
        self._bootstrap_admin_role()
        self._bootstrap_project_role_assignment()
        self._bootstrap_system_role_assignment()
        self._bootstrap_region()
        self._bootstrap_catalog()

    def _bootstrap_default_domain(self):
        default_domain = {
            'id': CONF.identity.default_domain_id,
            'name': 'Default',
            'enabled': True,
            'description': 'The default domain'
        }
        try:
            PROVIDERS.resource_api.create_domain(
                domain_id=default_domain['id'],
                domain=default_domain)
            LOG.info('Created domain %s', default_domain['id'])
        except exception.Conflict:
            # NOTE(morganfainberg): Domain already exists, continue on.
            LOG.info('Domain %s already exists, skipping creation.',
                     default_domain['id'])

        self.default_domain_id = default_domain['id']

    def _bootstrap_project(self):
        try:
            project_id = uuid.uuid4().hex
            project = {
                'enabled': True,
                'id': project_id,
                'domain_id': self.default_domain_id,
                'description': 'Bootstrap project for initializing the cloud.',
                'name': self.project_name
            }
            PROVIDERS.resource_api.create_project(project_id, project)
            LOG.info('Created project %s', self.project_name)
        except exception.Conflict:
            LOG.info('Project %s already exists, skipping creation.',
                     self.project_name)
            project = PROVIDERS.resource_api.get_project_by_name(
                self.project_name, self.default_domain_id
            )

        self.project_id = project['id']

    def _ensure_role_exists(self, role_name):
        # NOTE(morganfainberg): Do not create the role if it already exists.
        try:
            role_id = uuid.uuid4().hex
            role = {'name': role_name, 'id': role_id}
            if self.immutable_roles:
                role['options'] = {'immutable': True}
            role = PROVIDERS.role_api.create_role(role_id, role)
            LOG.info('Created role %s', role_name)
            if not self.immutable_roles:
                LOG.warning("Role %(role)s was created as a mutable role. It "
                            "is recommended to make this role immutable by "
                            "adding the 'immutable' resource option to this "
                            "role, or re-running this command without "
                            "--no-immutable-role.", {'role': role_name})
            return role
        except exception.Conflict:
            LOG.info('Role %s exists, skipping creation.', role_name)
            # NOTE(davechen): There is no backend method to get the role
            # by name, so build the hints to list the roles and filter by
            # name instead.
            hints = driver_hints.Hints()
            hints.add_filter('name', role_name)
            # Only return global roles, domain-specific roles can't be used in
            # system assignments and bootstrap isn't designed to work with
            # domain-specific roles.
            hints.add_filter('domain_id', None)

            # NOTE(lbragstad): Global roles are unique based on name. At this
            # point we should be safe to return the first, and only, element in
            # the list.
            return PROVIDERS.role_api.list_roles(hints)[0]

    def _ensure_implied_role(self, prior_role_id, implied_role_id):
        try:
            PROVIDERS.role_api.create_implied_role(prior_role_id,
                                                   implied_role_id)
            LOG.info(
                'Created implied role where %s implies %s',
                prior_role_id,
                implied_role_id
            )
        except exception.Conflict:
            LOG.info(
                'Implied role where %s implies %s exists, skipping creation.',
                prior_role_id,
                implied_role_id
            )

    def _bootstrap_reader_role(self):
        role = self._ensure_role_exists(self.reader_role_name)
        self.reader_role_id = role['id']

    def _bootstrap_member_role(self):
        role = self._ensure_role_exists(self.member_role_name)
        self.member_role_id = role['id']
        self._ensure_implied_role(self.member_role_id, self.reader_role_id)

    def _bootstrap_admin_role(self):
        role = self._ensure_role_exists(self.admin_role_name)
        self.admin_role_id = role['id']
        self._ensure_implied_role(self.admin_role_id, self.member_role_id)

    def _bootstrap_admin_user(self):
        # NOTE(morganfainberg): Do not create the user if it already exists.
        try:
            user = PROVIDERS.identity_api.get_user_by_name(
                self.admin_username, self.default_domain_id
            )
            LOG.info('User %s already exists, skipping creation.',
                     self.admin_username)

            # If the user is not enabled, re-enable them. This also helps
            # provide some useful logging output later.
            update = {}
            enabled = user['enabled']
            if not enabled:
                update['enabled'] = True

            try:
                PROVIDERS.identity_api.driver.authenticate(
                    user['id'], self.admin_password
                )
            except AssertionError:
                # This means that authentication failed and that we need to
                # update the user's password. This is going to persist a
                # revocation event that will make all previous tokens for the
                # user invalid, which is OK because it falls within the scope
                # of revocation. If a password changes, we shouldn't be able to
                # use tokens obtained with an old password.
                update['password'] = self.admin_password

            # Only make a call to update the user if the password has changed
            # or the user was previously disabled. This allows bootstrap to act
            # as a recovery tool, without having to create a new user.
            if update:
                user = PROVIDERS.identity_api.update_user(
                    user['id'], update
                )
                LOG.info('Reset password for user %s.', self.admin_username)
                if not enabled and user['enabled']:
                    # Although we always try to enable the user, this log
                    # message only makes sense if we know that the user was
                    # previously disabled.
                    LOG.info('Enabled user %s.', self.admin_username)
        except exception.UserNotFound:
            user = PROVIDERS.identity_api.create_user(
                user_ref={
                    'name': self.admin_username,
                    'enabled': True,
                    'domain_id': self.default_domain_id,
                    'password': self.admin_password
                }
            )
            LOG.info('Created user %s', self.admin_username)

        self.admin_user_id = user['id']

    def _bootstrap_project_role_assignment(self):
        try:
            PROVIDERS.assignment_api.add_role_to_user_and_project(
                user_id=self.admin_user_id,
                project_id=self.project_id,
                role_id=self.admin_role_id
            )
            LOG.info('Granted role %(role)s on project %(project)s to '
                     'user %(username)s.',
                     {'role': self.admin_role_name,
                      'project': self.project_name,
                      'username': self.admin_username})
        except exception.Conflict:
            LOG.info('User %(username)s already has role %(role)s on '
                     'project %(project)s.',
                     {'username': self.admin_username,
                      'role': self.admin_role_name,
                      'project': self.project_name})

    def _bootstrap_system_role_assignment(self):
        # NOTE(lbragstad): We need to make sure a user has at least one role on
        # the system. Otherwise it's possible for administrators to lock
        # themselves out of system-level APIs in their deployment. This is
        # considered backwards compatible because even if the assignment
        # exists, it needs to be enabled through oslo.policy configuration
        # options to be enforced.
        try:
            PROVIDERS.assignment_api.create_system_grant_for_user(
                self.admin_user_id, self.admin_role_id
            )
            LOG.info('Granted role %(role)s on the system to user'
                     ' %(username)s.',
                     {'role': self.admin_role_name,
                      'username': self.admin_username})
        except exception.Conflict:
            LOG.info('User %(username)s already has role %(role)s on '
                     'the system.',
                     {'username': self.admin_username,
                      'role': self.admin_role_name})

    def _bootstrap_region(self):
        if self.region_id:
            try:
                PROVIDERS.catalog_api.create_region(
                    region_ref={'id': self.region_id}
                )
                LOG.info('Created region %s', self.region_id)
            except exception.Conflict:
                LOG.info('Region %s exists, skipping creation.',
                         self.region_id)

    def _bootstrap_catalog(self):
        if self.public_url or self.admin_url or self.internal_url:
            hints = driver_hints.Hints()
            hints.add_filter('type', 'identity')
            services = PROVIDERS.catalog_api.list_services(hints)

            if services:
                service = services[0]

                hints = driver_hints.Hints()
                hints.add_filter('service_id', service['id'])
                if self.region_id:
                    hints.add_filter('region_id', self.region_id)

                endpoints = PROVIDERS.catalog_api.list_endpoints(hints)
            else:
                service_id = uuid.uuid4().hex
                service = {
                    'id': service_id, 'name': self.service_name,
                    'type': 'identity', 'enabled': True
                }

                PROVIDERS.catalog_api.create_service(service_id, service)
                endpoints = []

            self.service_id = service['id']
            available_interfaces = {e['interface']: e for e in endpoints}
            expected_endpoints = {'public': self.public_url,
                                  'internal': self.internal_url,
                                  'admin': self.admin_url}

            for interface, url in expected_endpoints.items():
                if not url:
                    # not specified to bootstrap command
                    continue

                try:
                    endpoint_ref = available_interfaces[interface]
                except KeyError:
                    endpoint_ref = {'id': uuid.uuid4().hex,
                                    'interface': interface,
                                    'url': url,
                                    'service_id': self.service_id,
                                    'enabled': True}

                    if self.region_id:
                        endpoint_ref['region_id'] = self.region_id

                    PROVIDERS.catalog_api.create_endpoint(
                        endpoint_id=endpoint_ref['id'],
                        endpoint_ref=endpoint_ref)

                    LOG.info('Created %(interface)s endpoint %(url)s',
                             {'interface': interface, 'url': url})
                else:
                    endpoint_ref['url'] = url
                    PROVIDERS.catalog_api.update_endpoint(
                        endpoint_id=endpoint_ref['id'],
                        endpoint_ref=endpoint_ref)
                    LOG.info('%s endpoint updated', interface)

                self.endpoints[interface] = endpoint_ref['id']

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

import http.client

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserOauth1ConsumerTests(object):
    """Common default functionality for all system users."""

    def test_user_can_get_consumer(self):
        ref = PROVIDERS.oauth_api.create_consumer(
            {'id': uuid.uuid4().hex})
        with self.test_client() as c:
            c.get('/v3/OS-OAUTH1/consumers/%s' % ref['id'],
                  headers=self.headers)

    def test_user_can_list_consumers(self):
        PROVIDERS.oauth_api.create_consumer(
            {'id': uuid.uuid4().hex})
        with self.test_client() as c:
            c.get('/v3/OS-OAUTH1/consumers',
                  headers=self.headers)


class _SystemReaderAndMemberOauth1ConsumerTests(object):

    def test_user_cannot_create_consumer(self):
        with self.test_client() as c:
            c.post('/v3/OS-OAUTH1/consumers',
                   json={'consumer': {}},
                   expected_status_code=http.client.FORBIDDEN,
                   headers=self.headers)

    def test_user_cannot_update_consumer(self):
        ref = PROVIDERS.oauth_api.create_consumer(
            {'id': uuid.uuid4().hex})
        with self.test_client() as c:
            c.patch('/v3/OS-OAUTH1/consumers/%s' % ref['id'],
                    json={'consumer': {'description': uuid.uuid4().hex}},
                    expected_status_code=http.client.FORBIDDEN,
                    headers=self.headers)

    def test_user_cannot_delete_consumer(self):
        ref = PROVIDERS.oauth_api.create_consumer(
            {'id': uuid.uuid4().hex})
        with self.test_client() as c:
            c.delete('/v3/OS-OAUTH1/consumers/%s' % ref['id'],
                     expected_status_code=http.client.FORBIDDEN,
                     headers=self.headers)


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserOauth1ConsumerTests,
                        _SystemReaderAndMemberOauth1ConsumerTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_reader
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_reader['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class SystemMemberTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserOauth1ConsumerTests,
                        _SystemReaderAndMemberOauth1ConsumerTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.user_id = PROVIDERS.identity_api.create_user(
            system_member
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.bootstrapper.member_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=system_member['password'],
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class SystemAdminTests(base_classes.TestCaseWithBootstrap,
                       common_auth.AuthTestMixin,
                       _SystemUserOauth1ConsumerTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        # Reuse the system administrator account created during
        # ``keystone-manage bootstrap``
        self.user_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.user_id,
            password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_create_consumer(self):
        with self.test_client() as c:
            c.post('/v3/OS-OAUTH1/consumers',
                   json={'consumer': {}},
                   headers=self.headers)

    def test_user_can_update_consumer(self):
        ref = PROVIDERS.oauth_api.create_consumer(
            {'id': uuid.uuid4().hex})
        with self.test_client() as c:
            c.patch('/v3/OS-OAUTH1/consumers/%s' % ref['id'],
                    json={'consumer': {'description': uuid.uuid4().hex}},
                    headers=self.headers)

    def test_user_can_delete_consumer(self):
        ref = PROVIDERS.oauth_api.create_consumer(
            {'id': uuid.uuid4().hex})
        with self.test_client() as c:
            c.delete('/v3/OS-OAUTH1/consumers/%s' % ref['id'],
                     headers=self.headers)

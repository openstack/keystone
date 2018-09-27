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

from six.moves import http_client

from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class _SystemUserDomainTests(object):

    def test_user_can_list_domains(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            r = c.get('/v3/domains', headers=self.headers)
            domain_ids = []
            for domain in r.json['domains']:
                domain_ids.append(domain['id'])
            self.assertIn(domain['id'], domain_ids)

    def test_user_can_filter_domains_by_name(self):
        domain_name = uuid.uuid4().hex
        domain = unit.new_domain_ref(name=domain_name)
        domain = PROVIDERS.resource_api.create_domain(domain['id'], domain)

        PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            r = c.get(
                '/v3/domains?name=%s' % domain_name,
                headers=self.headers
            )
            self.assertEqual(1, len(r.json['domains']))
            self.assertEqual(domain['id'], r.json['domains'][0]['id'])

    def test_user_can_filter_domains_by_enabled(self):
        enabled_domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        disabled_domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref(enabled=False)
        )

        with self.test_client() as c:
            r = c.get('/v3/domains?enabled=true', headers=self.headers)
            enabled_domain_ids = []
            for domain in r.json['domains']:
                enabled_domain_ids.append(domain['id'])
            self.assertIn(enabled_domain['id'], enabled_domain_ids)
            self.assertNotIn(disabled_domain['id'], enabled_domain_ids)

            r = c.get('/v3/domains?enabled=false', headers=self.headers)
            disabled_domain_ids = []
            for domain in r.json['domains']:
                disabled_domain_ids.append(domain['id'])
            self.assertIn(disabled_domain['id'], disabled_domain_ids)
            self.assertNotIn(enabled_domain['id'], disabled_domain_ids)

    def test_user_can_get_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            r = c.get('/v3/domains/%s' % domain['id'], headers=self.headers)
            self.assertEqual(domain['id'], r.json['domain']['id'])


class _SystemMemberAndReaderDomainTests(object):

    def test_user_cannot_create_a_domain(self):
        create = {'domain': {'name': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/domains', json=create, headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_update_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        update = {'domain': {'description': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/domains/%s' % domain['id'], json=update,
                headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )

    def test_user_cannot_delete_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            c.delete(
                '/v3/domains/%s' % domain['id'], headers=self.headers,
                expected_status_code=http_client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserDomainTests,
                        _SystemMemberAndReaderDomainTests):

    def setUp(self):
        super(SystemReaderTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_reader = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.system_reader_id = PROVIDERS.identity_api.create_user(
            system_reader
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.system_reader_id, self.bootstrapper.reader_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.system_reader_id, password=system_reader['password'],
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
                        _SystemUserDomainTests,
                        _SystemMemberAndReaderDomainTests):

    def setUp(self):
        super(SystemMemberTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        system_member = unit.new_user_ref(
            domain_id=CONF.identity.default_domain_id
        )
        self.system_member_id = PROVIDERS.identity_api.create_user(
            system_member
        )['id']
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.system_member_id, self.bootstrapper.member_role_id
        )

        auth = self.build_authentication_request(
            user_id=self.system_member_id, password=system_member['password'],
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
                       _SystemUserDomainTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self.system_admin_id = self.bootstrapper.admin_user_id
        auth = self.build_authentication_request(
            user_id=self.system_admin_id,
            password=self.bootstrapper.admin_password,
            system=True
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_update_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        update = {'domain': {'description': uuid.uuid4().hex}}
        with self.test_client() as c:
            c.patch(
                '/v3/domains/%s' % domain['id'], json=update,
                headers=self.headers
            )

    def test_user_can_create_a_domain(self):
        create = {'domain': {'name': uuid.uuid4().hex}}

        with self.test_client() as c:
            c.post(
                '/v3/domains', json=create, headers=self.headers
            )

    def test_user_can_delete_a_domain(self):
        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )

        with self.test_client() as c:
            update = {'domain': {'enabled': False}}
            path = '/v3/domains/%s' % domain['id']
            c.patch(path, json=update, headers=self.headers)
            c.delete(path, headers=self.headers)

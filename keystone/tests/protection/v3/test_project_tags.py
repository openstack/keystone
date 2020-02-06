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
from oslo_serialization import jsonutils

from keystone.common.policies import project as pp
from keystone.common import provider_api
import keystone.conf
from keystone.tests.common import auth as common_auth
from keystone.tests import unit
from keystone.tests.unit import base_classes
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import temporaryfile

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


def _override_policy(policy_file):
    # TODO(lbragstad): Remove this once the deprecated policies in
    # keystone.common.policies.project have been removed. This is only
    # here to make sure we test the new policies instead of the deprecated
    # ones. Oslo.policy will OR deprecated policies with new policies to
    # maintain compatibility and give operators a chance to update
    # permissions or update policies without breaking users. This will
    # cause these specific tests to fail since we're trying to correct this
    # broken behavior with better scope checking.
    with open(policy_file, 'w') as f:
        overridden_policies = {
            'identity:get_project_tag': (
                pp.SYSTEM_READER_OR_DOMAIN_READER_OR_PROJECT_USER
            ),
            'identity:list_project_tags': (
                pp.SYSTEM_READER_OR_DOMAIN_READER_OR_PROJECT_USER
            ),
            'identity:create_project_tag': (
                pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN_OR_PROJECT_ADMIN
            ),
            'identity:update_project_tags': (
                pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN_OR_PROJECT_ADMIN
            ),
            'identity:delete_project_tag': (
                pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN_OR_PROJECT_ADMIN
            ),
            'identity:delete_project_tags': (
                pp.SYSTEM_ADMIN_OR_DOMAIN_ADMIN_OR_PROJECT_ADMIN
            )
        }
        f.write(jsonutils.dumps(overridden_policies))


class _SystemUserTests(object):
    def test_user_can_get_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_list_project_tags(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers
            )
            self.assertTrue(len(r.json['tags']) == 1)
            self.assertEqual(tag, r.json['tags'][0])


class _SystemMemberAndReaderTagTests(object):

    def test_user_cannot_create_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        update = {"tags": [uuid.uuid4().hex]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update, expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainAndProjectUserTagTests(object):

    def test_user_cannot_create_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        update = {"tags": [uuid.uuid4().hex]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update, expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class SystemReaderTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _SystemUserTests,
                        _SystemMemberAndReaderTagTests):

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
                        _SystemUserTests,
                        _SystemMemberAndReaderTagTests):

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
                       _SystemUserTests):

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.loadapp()
        self.useFixture(ksfixtures.Policy(self.config_fixture))
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

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

    def test_user_can_create_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.CREATED
            )

    def test_user_can_update_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        update = {"tags": [uuid.uuid4().hex]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update,
                expected_status_code=http.client.OK
            )

    def test_user_can_delete_project_tag(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers
            )


class _DomainUserTagTests(object):

    def test_user_can_get_tag_for_project_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_list_tags_for_project_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers
            )
            self.assertTrue(len(r.json['tags']) == 1)
            self.assertEqual(tag, r.json['tags'][0])

    def test_user_cannot_create_project_tag_outside_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_project_tag_outside_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        new_tag = uuid.uuid4().hex
        update = {"tags": [new_tag]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update, expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_project_tag_outside_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_tag_for_project_outside_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_tags_for_project_outside_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags' % project['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _DomainMemberAndReaderTagTests(object):

    def test_user_cannot_create_project_tag_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_project_tag_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        new_tag = uuid.uuid4().hex
        update = {"tags": [new_tag]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update, expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_project_tag_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class DomainAdminUserTests(base_classes.TestCaseWithBootstrap,
                           common_auth.AuthTestMixin,
                           _DomainUserTagTests):

    def setUp(self):
        super(DomainAdminUserTests, self).setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )

        _override_policy(self.policy_file_name)
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_create_project_tag_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers, expected_status_code=http.client.CREATED
            )

    def test_user_can_update_project_tag_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        new_tag = uuid.uuid4().hex
        update = {"tags": [new_tag]}

        with self.test_client() as c:
            r = c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update, expected_status_code=http.client.OK
            )
            self.assertTrue(len(r.json['tags']) == 1)
            self.assertEqual(new_tag, r.json['tags'][0])

    def test_user_can_delete_project_tag_in_domain(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex, unit.new_project_ref(domain_id=self.domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers
            )


class DomainMemberUserTests(base_classes.TestCaseWithBootstrap,
                            common_auth.AuthTestMixin,
                            _DomainUserTagTests,
                            _DomainMemberAndReaderTagTests):

    def setUp(self):
        super(DomainMemberUserTests, self).setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )

        _override_policy(self.policy_file_name)
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class DomainReaderUserTests(base_classes.TestCaseWithBootstrap,
                            common_auth.AuthTestMixin,
                            _DomainUserTagTests,
                            _DomainMemberAndReaderTagTests):

    def setUp(self):
        super(DomainReaderUserTests, self).setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )

        _override_policy(self.policy_file_name)
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        domain = PROVIDERS.resource_api.create_domain(
            uuid.uuid4().hex, unit.new_domain_ref()
        )
        self.domain_id = domain['id']
        domain_admin = unit.new_user_ref(domain_id=self.domain_id)
        self.user_id = PROVIDERS.identity_api.create_user(domain_admin)['id']
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            domain_id=self.domain_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=domain_admin['password'],
            domain_id=self.domain_id,
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class _ProjectUserTagTests(object):

    def test_user_can_get_tag_for_project(self):
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(self.project_id, tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags/%s' % (self.project_id, tag),
                headers=self.headers,
                expected_status_code=http.client.NO_CONTENT
            )

    def test_user_can_list_tags_for_project(self):
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(self.project_id, tag)

        with self.test_client() as c:
            r = c.get(
                '/v3/projects/%s/tags' % self.project_id, headers=self.headers
            )
            self.assertTrue(len(r.json['tags']) == 1)
            self.assertEqual(tag, r.json['tags'][0])

    def test_user_cannot_create_tag_for_other_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_tag_for_other_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        update = {"tags": [uuid.uuid4().hex]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % project['id'], headers=self.headers,
                json=update, expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_tag_for_other_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_get_tag_for_other_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags/%s' % (project['id'], tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_list_tags_for_other_project(self):
        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )

        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(project['id'], tag)

        with self.test_client() as c:
            c.get(
                '/v3/projects/%s/tags' % project['id'],
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class _ProjectMemberAndReaderTagTests(object):

    def test_user_cannot_create_project_tag(self):
        tag = uuid.uuid4().hex
        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (self.project_id, tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_update_project_tag(self):
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(self.project_id, tag)

        update = {"tags": [uuid.uuid4().hex]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % self.project_id, headers=self.headers,
                json=update, expected_status_code=http.client.FORBIDDEN
            )

    def test_user_cannot_delete_project_tag(self):
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(self.project_id, tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (self.project_id, tag),
                headers=self.headers,
                expected_status_code=http.client.FORBIDDEN
            )


class ProjectAdminTests(base_classes.TestCaseWithBootstrap,
                        common_auth.AuthTestMixin,
                        _ProjectUserTagTests):

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        _override_policy(self.policy_file_name)
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        self.user_id = self.bootstrapper.admin_user_id
        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.admin_role_id, user_id=self.user_id,
            project_id=self.bootstrapper.project_id
        )
        self.project_id = self.bootstrapper.project_id

        auth = self.build_authentication_request(
            user_id=self.user_id, password=self.bootstrapper.admin_password,
            project_id=self.bootstrapper.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

    def test_user_can_create_project_tag(self):
        tag = uuid.uuid4().hex
        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags/%s' % (self.project_id, tag),
                headers=self.headers, expected_status_code=http.client.CREATED
            )

    def test_user_can_update_project_tag(self):
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(self.project_id, tag)

        update = {"tags": [uuid.uuid4().hex]}

        with self.test_client() as c:
            c.put(
                '/v3/projects/%s/tags' % self.project_id, headers=self.headers,
                json=update, expected_status_code=http.client.OK
            )

    def test_user_can_delete_project_tag(self):
        tag = uuid.uuid4().hex
        PROVIDERS.resource_api.create_project_tag(self.project_id, tag)

        with self.test_client() as c:
            c.delete(
                '/v3/projects/%s/tags/%s' % (self.project_id, tag),
                headers=self.headers
            )


class ProjectMemberTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _ProjectUserTagTests,
                         _ProjectMemberAndReaderTagTests):

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        _override_policy(self.policy_file_name)
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )
        self.project_id = project['id']
        self.user_id = self.bootstrapper.admin_user_id

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.member_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=self.bootstrapper.admin_password,
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}


class ProjectReaderTests(base_classes.TestCaseWithBootstrap,
                         common_auth.AuthTestMixin,
                         _ProjectUserTagTests,
                         _ProjectMemberAndReaderTagTests):

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.loadapp()

        self.policy_file = self.useFixture(temporaryfile.SecureTempFile())
        self.policy_file_name = self.policy_file.file_name
        self.useFixture(
            ksfixtures.Policy(
                self.config_fixture, policy_file=self.policy_file_name
            )
        )
        _override_policy(self.policy_file_name)
        self.config_fixture.config(group='oslo_policy', enforce_scope=True)

        project = PROVIDERS.resource_api.create_project(
            uuid.uuid4().hex,
            unit.new_project_ref(domain_id=CONF.identity.default_domain_id)
        )
        self.project_id = project['id']
        self.user_id = self.bootstrapper.admin_user_id

        PROVIDERS.assignment_api.create_grant(
            self.bootstrapper.reader_role_id, user_id=self.user_id,
            project_id=self.project_id
        )

        auth = self.build_authentication_request(
            user_id=self.user_id, password=self.bootstrapper.admin_password,
            project_id=self.project_id
        )

        # Grab a token using the persona we're testing and prepare headers
        # for requests we'll be making in the tests.
        with self.test_client() as c:
            r = c.post('/v3/auth/tokens', json=auth)
            self.token_id = r.headers['X-Subject-Token']
            self.headers = {'X-Auth-Token': self.token_id}

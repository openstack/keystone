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

import http.client
from testtools import matchers

from keystone.common import provider_api
import keystone.conf
from keystone.credential.providers import fernet as credential_fernet
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit import test_v3
from keystone.tests.unit import utils as test_utils


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class ResourceTestCase(test_v3.RestfulTestCase,
                       test_v3.AssignmentTestMixin):
    """Test domains and projects."""

    def setUp(self):
        super(ResourceTestCase, self).setUp()
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'credential',
                credential_fernet.MAX_ACTIVE_KEYS
            )
        )

    # Domain CRUD tests

    def test_create_domain(self):
        """Call ``POST /domains``."""
        ref = unit.new_domain_ref()
        r = self.post(
            '/domains',
            body={'domain': ref})
        return self.assertValidDomainResponse(r, ref)

    def test_create_domain_case_sensitivity(self):
        """Call `POST /domains`` twice with upper() and lower() cased name."""
        ref = unit.new_domain_ref()

        # ensure the name is lowercase
        ref['name'] = ref['name'].lower()
        r = self.post(
            '/domains',
            body={'domain': ref})
        self.assertValidDomainResponse(r, ref)

        # ensure the name is uppercase
        ref['name'] = ref['name'].upper()
        r = self.post(
            '/domains',
            body={'domain': ref})
        self.assertValidDomainResponse(r, ref)

    def test_create_domain_bad_request(self):
        """Call ``POST /domains``."""
        self.post('/domains', body={'domain': {}},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_domain_unsafe(self):
        """Call ``POST /domains with unsafe names``."""
        unsafe_name = 'i am not / safe'

        self.config_fixture.config(group='resource',
                                   domain_name_url_safe='off')
        ref = unit.new_domain_ref(name=unsafe_name)
        self.post(
            '/domains',
            body={'domain': ref})

        for config_setting in ['new', 'strict']:
            self.config_fixture.config(group='resource',
                                       domain_name_url_safe=config_setting)
            ref = unit.new_domain_ref(name=unsafe_name)
            self.post(
                '/domains',
                body={'domain': ref},
                expected_status=http.client.BAD_REQUEST)

    def test_create_domain_unsafe_default(self):
        """Check default for unsafe names for ``POST /domains``."""
        unsafe_name = 'i am not / safe'

        # By default, we should be able to create unsafe names
        ref = unit.new_domain_ref(name=unsafe_name)
        self.post(
            '/domains',
            body={'domain': ref})

    def test_create_domain_creates_is_domain_project(self):
        """Check a project that acts as a domain is created.

        Call ``POST /domains``.
        """
        # Create a new domain
        domain_ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': domain_ref})
        self.assertValidDomainResponse(r, domain_ref)

        # Retrieve its correspondent project
        r = self.get('/projects/%(project_id)s' % {
            'project_id': r.result['domain']['id']})
        self.assertValidProjectResponse(r)

        # The created project has is_domain flag as True
        self.assertTrue(r.result['project']['is_domain'])

        # And its parent_id and domain_id attributes are equal
        self.assertIsNone(r.result['project']['parent_id'])
        self.assertIsNone(r.result['project']['domain_id'])

    def test_create_is_domain_project_creates_domain(self):
        """Call ``POST /projects`` is_domain and check a domain is created."""
        # Create a new project that acts as a domain
        project_ref = unit.new_project_ref(domain_id=None, is_domain=True)
        r = self.post('/projects', body={'project': project_ref})
        self.assertValidProjectResponse(r)

        # Retrieve its correspondent domain
        r = self.get('/domains/%(domain_id)s' % {
            'domain_id': r.result['project']['id']})
        self.assertValidDomainResponse(r)
        self.assertIsNotNone(r.result['domain'])

    def test_create_domain_valid_explicit_id(self):
        """Call ``POST /domains`` with a valid `explicit_domain_id` set."""
        ref = unit.new_domain_ref()
        explicit_domain_id = '9aea63518f0040c6b4518d8d2242911c'

        ref['explicit_domain_id'] = explicit_domain_id
        r = self.post(
            '/domains',
            body={'domain': ref})
        self.assertValidDomainResponse(r, ref)

        r = self.get('/domains/%(domain_id)s' % {
            'domain_id': explicit_domain_id})
        self.assertValidDomainResponse(r)
        self.assertIsNotNone(r.result['domain'])

    def test_create_second_domain_valid_explicit_id_fails(self):
        """Call ``POST /domains`` with a valid `explicit_domain_id` set."""
        ref = unit.new_domain_ref()
        explicit_domain_id = '9aea63518f0040c6b4518d8d2242911c'

        ref['explicit_domain_id'] = explicit_domain_id
        r = self.post(
            '/domains',
            body={'domain': ref})
        self.assertValidDomainResponse(r, ref)

        # second one should fail
        r = self.post(
            '/domains',
            body={'domain': ref},
            expected_status=http.client.CONFLICT)

    def test_create_domain_invalid_explicit_ids(self):
        """Call ``POST /domains`` with various invalid explicit_domain_ids."""
        ref = unit.new_domain_ref()

        bad_ids = ['bad!',
                   '',
                   '9aea63518f0040c',
                   '1234567890123456789012345678901234567890',
                   '9aea63518f0040c6b4518d8d2242911c9aea63518f0040c6b45']

        for explicit_domain_id in bad_ids:
            ref['explicit_domain_id'] = explicit_domain_id
            self.post('/domains', body={'domain': {}},
                      expected_status=http.client.BAD_REQUEST)

    def test_list_head_domains(self):
        """Call ``GET & HEAD /domains``."""
        resource_url = '/domains'
        r = self.get(resource_url)
        self.assertValidDomainListResponse(r, ref=self.domain,
                                           resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_list_limit_for_domains(self):
        for x in range(6):
            domain = {'domain': unit.new_domain_ref()}
            self.post('/domains', body=domain)

        for expected_length in range(1, 6):
            self.config_fixture.config(
                group='resource', list_limit=expected_length
            )
            response = self.get('/domains')
            domain_list = response.json_body['domains']
            self.assertEqual(expected_length, len(domain_list))

    def test_get_head_domain(self):
        """Call ``GET /domains/{domain_id}``."""
        resource_url = '/domains/%(domain_id)s' % {
            'domain_id': self.domain_id}
        r = self.get(resource_url)
        self.assertValidDomainResponse(r, self.domain)
        self.head(resource_url, expected_status=http.client.OK)

    def test_update_domain(self):
        """Call ``PATCH /domains/{domain_id}``."""
        ref = unit.new_domain_ref()
        del ref['id']
        r = self.patch('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id},
            body={'domain': ref})
        self.assertValidDomainResponse(r, ref)

    def test_update_domain_unsafe(self):
        """Call ``POST /domains/{domain_id} with unsafe names``."""
        unsafe_name = 'i am not / safe'

        self.config_fixture.config(group='resource',
                                   domain_name_url_safe='off')
        ref = unit.new_domain_ref(name=unsafe_name)
        del ref['id']
        self.patch('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id},
            body={'domain': ref})

        unsafe_name = 'i am still not / safe'
        for config_setting in ['new', 'strict']:
            self.config_fixture.config(group='resource',
                                       domain_name_url_safe=config_setting)
            ref = unit.new_domain_ref(name=unsafe_name)
            del ref['id']
            self.patch('/domains/%(domain_id)s' % {
                'domain_id': self.domain_id},
                body={'domain': ref},
                expected_status=http.client.BAD_REQUEST)

    def test_update_domain_unsafe_default(self):
        """Check default for unsafe names for ``POST /domains``."""
        unsafe_name = 'i am not / safe'

        # By default, we should be able to create unsafe names
        ref = unit.new_domain_ref(name=unsafe_name)
        del ref['id']
        self.patch('/domains/%(domain_id)s' % {
            'domain_id': self.domain_id},
            body={'domain': ref})

    def test_update_domain_updates_is_domain_project(self):
        """Check the project that acts as a domain is updated.

        Call ``PATCH /domains``.
        """
        # Create a new domain
        domain_ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': domain_ref})
        self.assertValidDomainResponse(r, domain_ref)

        # Disable it
        self.patch('/domains/%s' % r.result['domain']['id'],
                   body={'domain': {'enabled': False}})

        # Retrieve its correspondent project
        r = self.get('/projects/%(project_id)s' % {
            'project_id': r.result['domain']['id']})
        self.assertValidProjectResponse(r)

        # The created project is disabled as well
        self.assertFalse(r.result['project']['enabled'])

    def test_disable_domain(self):
        """Call ``PATCH /domains/{domain_id}`` (set enabled=False)."""
        # Create a 2nd set of entities in a 2nd domain
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)

        project2 = unit.new_project_ref(domain_id=domain2['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)

        user2 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=domain2['id'],
                                 project_id=project2['id'])

        role_member = unit.new_role_ref()
        PROVIDERS.role_api.create_role(role_member['id'], role_member)

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            user2['id'], project2['id'], role_member['id']
        )

        # First check a user in that domain can authenticate..
        auth_data = self.build_authentication_request(
            user_id=user2['id'],
            password=user2['password'],
            project_id=project2['id'])
        self.v3_create_token(auth_data)

        # Now disable the domain
        domain2['enabled'] = False
        r = self.patch('/domains/%(domain_id)s' % {
            'domain_id': domain2['id']},
            body={'domain': {'enabled': False}})
        self.assertValidDomainResponse(r, domain2)

        # Try looking up in v3 by name and id
        auth_data = self.build_authentication_request(
            user_id=user2['id'],
            password=user2['password'],
            project_id=project2['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

        auth_data = self.build_authentication_request(
            username=user2['name'],
            user_domain_id=domain2['id'],
            password=user2['password'],
            project_id=project2['id'])
        self.v3_create_token(auth_data,
                             expected_status=http.client.UNAUTHORIZED)

    def test_delete_enabled_domain_fails(self):
        """Call ``DELETE /domains/{domain_id}`` (when domain enabled)."""
        # Try deleting an enabled domain, which should fail
        self.delete('/domains/%(domain_id)s' % {
            'domain_id': self.domain['id']},
            expected_status=exception.ForbiddenAction.code)

    def test_delete_domain(self):
        """Call ``DELETE /domains/{domain_id}``.

        The sample data set up already has a user and project that is part of
        self.domain. Additionally we will create a group and a credential
        within it. Since we will authenticate in this domain,
        we create another set of entities in a second domain.  Deleting this
        second domain should delete all these new entities. In addition,
        all the entities in the regular self.domain should be unaffected
        by the delete.

        Test Plan:

        - Create domain2 and a 2nd set of entities
        - Disable domain2
        - Delete domain2
        - Check entities in domain2 have been deleted
        - Check entities in self.domain are unaffected

        """
        # Create a group and a credential in the main domain
        group = unit.new_group_ref(domain_id=self.domain_id)
        group = PROVIDERS.identity_api.create_group(group)

        credential = unit.new_credential_ref(user_id=self.user['id'],
                                             project_id=self.project_id)
        PROVIDERS.credential_api.create_credential(
            credential['id'], credential
        )

        # Create a 2nd set of entities in a 2nd domain
        domain2 = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain2['id'], domain2)

        project2 = unit.new_project_ref(domain_id=domain2['id'])
        project2 = PROVIDERS.resource_api.create_project(
            project2['id'], project2
        )

        user2 = unit.new_user_ref(domain_id=domain2['id'],
                                  project_id=project2['id'])
        user2 = PROVIDERS.identity_api.create_user(user2)

        group2 = unit.new_group_ref(domain_id=domain2['id'])
        group2 = PROVIDERS.identity_api.create_group(group2)

        credential2 = unit.new_credential_ref(user_id=user2['id'],
                                              project_id=project2['id'])
        PROVIDERS.credential_api.create_credential(
            credential2['id'], credential2
        )

        # Now disable the new domain and delete it
        domain2['enabled'] = False
        r = self.patch('/domains/%(domain_id)s' % {
            'domain_id': domain2['id']},
            body={'domain': {'enabled': False}})
        self.assertValidDomainResponse(r, domain2)
        self.delete('/domains/%(domain_id)s' % {'domain_id': domain2['id']})

        # Check all the domain2 relevant entities are gone
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          domain2['id'])
        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          project2['id'])
        self.assertRaises(exception.GroupNotFound,
                          PROVIDERS.identity_api.get_group,
                          group2['id'])
        self.assertRaises(exception.UserNotFound,
                          PROVIDERS.identity_api.get_user,
                          user2['id'])
        self.assertRaises(exception.CredentialNotFound,
                          PROVIDERS.credential_api.get_credential,
                          credential2['id'])

        # ...and that all self.domain entities are still here
        r = PROVIDERS.resource_api.get_domain(self.domain['id'])
        self.assertDictEqual(self.domain, r)
        r = PROVIDERS.resource_api.get_project(self.project['id'])
        self.assertDictEqual(self.project, r)
        r = PROVIDERS.identity_api.get_group(group['id'])
        self.assertDictEqual(group, r)
        r = PROVIDERS.identity_api.get_user(self.user['id'])
        self.user.pop('password')
        self.assertDictEqual(self.user, r)
        r = PROVIDERS.credential_api.get_credential(credential['id'])
        self.assertDictEqual(credential, r)

    def test_delete_domain_with_idp(self):
        # Create a new domain
        domain_ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': domain_ref})
        self.assertValidDomainResponse(r, domain_ref)
        domain_id = r.result['domain']['id']
        # Create a Idp in the domain
        self.put('/OS-FEDERATION/identity_providers/test_idp',
                 body={"identity_provider": {
                     "domain_id": domain_id}},
                 expected_status=http.client.CREATED)
        # Disable and delete the domain with no error.
        self.patch('/domains/%(domain_id)s' % {
            'domain_id': domain_id},
            body={'domain': {'enabled': False}})
        self.delete('/domains/%s' % domain_id)
        # The Idp is deleted as well
        self.get('/OS-FEDERATION/identity_providers/test_idp',
                 expected_status=http.client.NOT_FOUND)

    def test_delete_domain_deletes_is_domain_project(self):
        """Check the project that acts as a domain is deleted.

        Call ``DELETE /domains``.
        """
        # Create a new domain
        domain_ref = unit.new_domain_ref()
        r = self.post('/domains', body={'domain': domain_ref})
        self.assertValidDomainResponse(r, domain_ref)

        # Retrieve its correspondent project
        self.get('/projects/%(project_id)s' % {
            'project_id': r.result['domain']['id']})

        # Delete the domain
        self.patch('/domains/%s' % r.result['domain']['id'],
                   body={'domain': {'enabled': False}})
        self.delete('/domains/%s' % r.result['domain']['id'])

        # The created project is deleted as well
        self.get('/projects/%(project_id)s' % {
            'project_id': r.result['domain']['id']}, expected_status=404)

    def test_delete_default_domain(self):
        # Need to disable it first.
        self.patch('/domains/%(domain_id)s' % {
            'domain_id': CONF.identity.default_domain_id},
            body={'domain': {'enabled': False}})

        self.delete(
            '/domains/%(domain_id)s' % {
                'domain_id': CONF.identity.default_domain_id})

    def test_token_revoked_once_domain_disabled(self):
        """Test token from a disabled domain has been invalidated.

        Test that a token that was valid for an enabled domain
        becomes invalid once that domain is disabled.

        """
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        user2 = unit.create_user(PROVIDERS.identity_api,
                                 domain_id=domain['id'])

        # build a request body
        auth_body = self.build_authentication_request(
            user_id=user2['id'],
            password=user2['password'])

        # sends a request for the user's token
        token_resp = self.post('/auth/tokens', body=auth_body)

        subject_token = token_resp.headers.get('x-subject-token')

        # validates the returned token and it should be valid.
        self.head('/auth/tokens',
                  headers={'x-subject-token': subject_token},
                  expected_status=http.client.OK)

        # now disable the domain
        domain['enabled'] = False
        url = "/domains/%(domain_id)s" % {'domain_id': domain['id']}
        self.patch(url,
                   body={'domain': {'enabled': False}})

        # validates the same token again and it should be 'not found'
        # as the domain has already been disabled.
        self.head('/auth/tokens',
                  headers={'x-subject-token': subject_token},
                  expected_status=http.client.NOT_FOUND)

    def test_delete_domain_hierarchy(self):
        """Call ``DELETE /domains/{domain_id}``."""
        domain = unit.new_domain_ref()
        PROVIDERS.resource_api.create_domain(domain['id'], domain)

        root_project = unit.new_project_ref(domain_id=domain['id'])
        root_project = PROVIDERS.resource_api.create_project(
            root_project['id'], root_project
        )

        leaf_project = unit.new_project_ref(
            domain_id=domain['id'],
            parent_id=root_project['id'])
        PROVIDERS.resource_api.create_project(leaf_project['id'], leaf_project)

        # Need to disable it first.
        self.patch('/domains/%(domain_id)s' % {
            'domain_id': domain['id']},
            body={'domain': {'enabled': False}})

        self.delete(
            '/domains/%(domain_id)s' % {
                'domain_id': domain['id']})

        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.get_domain,
                          domain['id'])

        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          root_project['id'])

        self.assertRaises(exception.ProjectNotFound,
                          PROVIDERS.resource_api.get_project,
                          leaf_project['id'])

    def test_forbid_operations_on_federated_domain(self):
        """Make sure one cannot operate on federated domain.

        This includes operations like create, update, delete
        on domain identified by id and name where difference variations of
        id 'Federated' are used.

        """
        def create_domains():
            for variation in ('Federated', 'FEDERATED',
                              'federated', 'fEderated'):
                domain = unit.new_domain_ref()
                domain['id'] = variation
                yield domain

        for domain in create_domains():
            self.assertRaises(
                AssertionError, PROVIDERS.resource_api.create_domain,
                domain['id'], domain)
            self.assertRaises(
                AssertionError, PROVIDERS.resource_api.update_domain,
                domain['id'], domain)
            self.assertRaises(
                exception.DomainNotFound, PROVIDERS.resource_api.delete_domain,
                domain['id'])

            # swap 'name' with 'id' and try again, expecting the request to
            # gracefully fail
            domain['id'], domain['name'] = domain['name'], domain['id']
            self.assertRaises(
                AssertionError, PROVIDERS.resource_api.create_domain,
                domain['id'], domain)
            self.assertRaises(
                AssertionError, PROVIDERS.resource_api.update_domain,
                domain['id'], domain)
            self.assertRaises(
                exception.DomainNotFound, PROVIDERS.resource_api.delete_domain,
                domain['id'])

    def test_forbid_operations_on_defined_federated_domain(self):
        """Make sure one cannot operate on a user-defined federated domain.

        This includes operations like create, update, delete.

        """
        non_default_name = 'beta_federated_domain'
        self.config_fixture.config(group='federation',
                                   federated_domain_name=non_default_name)
        domain = unit.new_domain_ref(name=non_default_name)
        self.assertRaises(AssertionError,
                          PROVIDERS.resource_api.create_domain,
                          domain['id'], domain)
        self.assertRaises(exception.DomainNotFound,
                          PROVIDERS.resource_api.delete_domain,
                          domain['id'])
        self.assertRaises(AssertionError,
                          PROVIDERS.resource_api.update_domain,
                          domain['id'], domain)

    # Project CRUD tests

    def test_list_head_projects(self):
        """Call ``GET & HEAD /projects``."""
        resource_url = '/projects'
        r = self.get(resource_url)
        self.assertValidProjectListResponse(r, ref=self.project,
                                            resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_create_project(self):
        """Call ``POST /projects``."""
        ref = unit.new_project_ref(domain_id=self.domain_id)
        r = self.post(
            '/projects',
            body={'project': ref})
        self.assertValidProjectResponse(r, ref)

    def test_create_project_bad_request(self):
        """Call ``POST /projects``."""
        self.post('/projects', body={'project': {}},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_project_invalid_domain_id(self):
        """Call ``POST /projects``."""
        ref = unit.new_project_ref(domain_id=uuid.uuid4().hex)
        self.post('/projects', body={'project': ref},
                  expected_status=http.client.BAD_REQUEST)

    def test_create_project_unsafe(self):
        """Call ``POST /projects with unsafe names``."""
        unsafe_name = 'i am not / safe'

        self.config_fixture.config(group='resource',
                                   project_name_url_safe='off')
        ref = unit.new_project_ref(name=unsafe_name)
        self.post(
            '/projects',
            body={'project': ref})

        for config_setting in ['new', 'strict']:
            self.config_fixture.config(group='resource',
                                       project_name_url_safe=config_setting)
            ref = unit.new_project_ref(name=unsafe_name)
            self.post(
                '/projects',
                body={'project': ref},
                expected_status=http.client.BAD_REQUEST)

    def test_create_project_unsafe_default(self):
        """Check default for unsafe names for ``POST /projects``."""
        unsafe_name = 'i am not / safe'

        # By default, we should be able to create unsafe names
        ref = unit.new_project_ref(name=unsafe_name)
        self.post(
            '/projects',
            body={'project': ref})

    def test_create_project_with_parent_id_none_and_domain_id_none(self):
        """Call ``POST /projects``."""
        # Grant a domain role for the user
        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domain_id,
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}
        self.put(member_url)

        # Create an authentication request for a domain scoped token
        auth = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain_id)

        # Without parent_id and domain_id passed as None, the domain_id should
        # be normalized to the domain on the token, when using a domain
        # scoped token.
        ref = unit.new_project_ref()
        r = self.post(
            '/projects',
            auth=auth,
            body={'project': ref})
        ref['domain_id'] = self.domain['id']
        self.assertValidProjectResponse(r, ref)

    def test_create_project_without_parent_id_and_without_domain_id(self):
        """Call ``POST /projects``."""
        # Grant a domain role for the user
        collection_url = (
            '/domains/%(domain_id)s/users/%(user_id)s/roles' % {
                'domain_id': self.domain_id,
                'user_id': self.user['id']})
        member_url = '%(collection_url)s/%(role_id)s' % {
            'collection_url': collection_url,
            'role_id': self.role_id}
        self.put(member_url)

        # Create an authentication request for a domain scoped token
        auth = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            domain_id=self.domain_id)

        # Without domain_id and parent_id, the domain_id should be
        # normalized to the domain on the token, when using a domain
        # scoped token.
        ref = unit.new_project_ref()
        r = self.post(
            '/projects',
            auth=auth,
            body={'project': ref})
        ref['domain_id'] = self.domain['id']
        self.assertValidProjectResponse(r, ref)

    @test_utils.wip('waiting for support for parent_id to imply domain_id')
    def test_create_project_with_parent_id_and_no_domain_id(self):
        """Call ``POST /projects``."""
        # With only the parent_id, the domain_id should be
        # normalized to the parent's domain_id
        ref_child = unit.new_project_ref(parent_id=self.project['id'])

        r = self.post(
            '/projects',
            body={'project': ref_child})
        self.assertEqual(self.project['domain_id'],
                         r.result['project']['domain_id'])
        ref_child['domain_id'] = self.domain['id']
        self.assertValidProjectResponse(r, ref_child)

    def _create_projects_hierarchy(self, hierarchy_size=1):
        """Create a single-branched project hierarchy with the specified size.

        :param hierarchy_size: the desired hierarchy size, default is 1 -
                               a project with one child.

        :returns projects: a list of the projects in the created hierarchy.

        """
        new_ref = unit.new_project_ref(domain_id=self.domain_id)
        resp = self.post('/projects', body={'project': new_ref})

        projects = [resp.result]

        for i in range(hierarchy_size):
            new_ref = unit.new_project_ref(
                domain_id=self.domain_id,
                parent_id=projects[i]['project']['id'])
            resp = self.post('/projects',
                             body={'project': new_ref})
            self.assertValidProjectResponse(resp, new_ref)

            projects.append(resp.result)

        return projects

    def _create_project_and_tags(self, num_of_tags=1):
        """Create a project and a number of tags attached to that project.

        :param num_of_tags: the desired number of tags created with a specified
                            project.

        :returns: A tuple containing a new project and a list of
                  random tags
        """
        tags = [uuid.uuid4().hex for i in range(num_of_tags)]
        ref = unit.new_project_ref(
            domain_id=self.domain_id,
            tags=tags)
        resp = self.post('/projects', body={'project': ref})
        return resp.result['project'], tags

    def test_list_project_response_returns_tags(self):
        """Call ``GET /projects`` should always return tag attributes."""
        tagged_project, tags = self._create_project_and_tags()
        self.get('/projects')
        ref = unit.new_project_ref(domain_id=self.domain_id)
        untagged_project = self.post(
            '/projects', body={'project': ref}
        ).json_body['project']
        resp = self.get('/projects')
        for project in resp.json_body['projects']:
            if project['id'] == tagged_project['id']:
                self.assertIsNotNone(project['tags'])
                self.assertEqual(project['tags'], tags)
            if project['id'] == untagged_project['id']:
                self.assertEqual(project['tags'], [])

    def test_list_projects_filtering_by_tags(self):
        """Call ``GET /projects?tags={tags}``."""
        project, tags = self._create_project_and_tags(num_of_tags=2)
        tag_string = ','.join(tags)
        resp = self.get('/projects?tags=%(values)s' % {
            'values': tag_string})
        self.assertValidProjectListResponse(resp)
        self.assertEqual(project['id'], resp.result['projects'][0]['id'])

    def test_list_projects_filtering_by_tags_any(self):
        """Call ``GET /projects?tags-any={tags}``."""
        project, tags = self._create_project_and_tags(num_of_tags=2)
        project1, tags1 = self._create_project_and_tags(num_of_tags=2)
        tag_string = tags[0] + ',' + tags1[0]
        resp = self.get('/projects?tags-any=%(values)s' % {
            'values': tag_string})
        pids = [p['id'] for p in resp.result['projects']]
        self.assertValidProjectListResponse(resp)
        self.assertIn(project['id'], pids)
        self.assertIn(project1['id'], pids)

    def test_list_projects_filtering_by_not_tags(self):
        """Call ``GET /projects?not-tags={tags}``."""
        project1, tags1 = self._create_project_and_tags(num_of_tags=2)
        project2, tags2 = self._create_project_and_tags(num_of_tags=2)
        tag_string = ','.join(tags1)
        resp = self.get('/projects?not-tags=%(values)s' % {
            'values': tag_string})
        self.assertValidProjectListResponse(resp)
        pids = [p['id'] for p in resp.result['projects']]
        self.assertNotIn(project1['id'], pids)
        self.assertIn(project2['id'], pids)

    def test_list_projects_filtering_by_not_tags_any(self):
        """Call ``GET /projects?not-tags-any={tags}``."""
        project1, tags1 = self._create_project_and_tags(num_of_tags=2)
        project2, tags2 = self._create_project_and_tags(num_of_tags=2)
        project3, tags3 = self._create_project_and_tags(num_of_tags=2)
        tag_string = tags1[0] + ',' + tags2[0]
        resp = self.get('/projects?not-tags-any=%(values)s' % {
            'values': tag_string})
        self.assertValidProjectListResponse(resp)
        pids = [p['id'] for p in resp.result['projects']]
        self.assertNotIn(project1['id'], pids)
        self.assertNotIn(project2['id'], pids)
        self.assertIn(project3['id'], pids)

    def test_list_projects_filtering_multiple_tag_filters(self):
        """Call ``GET /projects?tags={tags}&tags-any={tags}``."""
        project1, tags1 = self._create_project_and_tags(num_of_tags=2)
        project2, tags2 = self._create_project_and_tags(num_of_tags=2)
        project3, tags3 = self._create_project_and_tags(num_of_tags=2)
        tags1_query = ','.join(tags1)
        resp = self.patch('/projects/%(project_id)s' %
                          {'project_id': project3['id']},
                          body={'project': {'tags': tags1}})
        tags1.append(tags2[0])
        resp = self.patch('/projects/%(project_id)s' %
                          {'project_id': project1['id']},
                          body={'project': {'tags': tags1}})
        url = '/projects?tags=%(value1)s&tags-any=%(value2)s'
        resp = self.get(url % {'value1': tags1_query,
                               'value2': ','.join(tags2)})
        self.assertValidProjectListResponse(resp)
        self.assertEqual(len(resp.result['projects']), 1)
        self.assertIn(project1['id'], resp.result['projects'][0]['id'])

    def test_list_projects_filtering_multiple_any_tag_filters(self):
        """Call ``GET /projects?tags-any={tags}&not-tags-any={tags}``."""
        project1, tags1 = self._create_project_and_tags()
        project2, tags2 = self._create_project_and_tags(num_of_tags=2)
        url = '/projects?tags-any=%(value1)s&not-tags-any=%(value2)s'
        resp = self.get(url % {'value1': tags1[0],
                               'value2': tags2[0]})
        self.assertValidProjectListResponse(resp)
        pids = [p['id'] for p in resp.result['projects']]
        self.assertIn(project1['id'], pids)
        self.assertNotIn(project2['id'], pids)

    def test_list_projects_filtering_conflict_tag_filters(self):
        """Call ``GET /projects?tags={tags}&not-tags={tags}``."""
        project, tags = self._create_project_and_tags(num_of_tags=2)
        tag_string = ','.join(tags)
        url = '/projects?tags=%(values)s&not-tags=%(values)s'
        resp = self.get(url % {'values': tag_string})
        self.assertValidProjectListResponse(resp)
        self.assertEqual(len(resp.result['projects']), 0)

    def test_list_projects_filtering_conflict_any_tag_filters(self):
        """Call ``GET /projects?tags-any={tags}&not-tags-any={tags}``."""
        project, tags = self._create_project_and_tags(num_of_tags=2)
        tag_string = ','.join(tags)
        url = '/projects?tags-any=%(values)s&not-tags-any=%(values)s'
        resp = self.get(url % {'values': tag_string})
        self.assertValidProjectListResponse(resp)
        self.assertEqual(len(resp.result['projects']), 0)

    def test_list_projects_by_tags_and_name(self):
        """Call ``GET /projects?tags-any={tags}&name={name}``."""
        project, tags = self._create_project_and_tags(num_of_tags=2)
        ref = {'project': {'name': 'tags and name'}}
        resp = self.patch('/projects/%(project_id)s' %
                          {'project_id': project['id']},
                          body=ref)
        url = '/projects?tags-any=%(values)s&name=%(name)s'
        resp = self.get(url % {'values': tags[0],
                               'name': 'tags and name'})
        self.assertValidProjectListResponse(resp)
        pids = [p['id'] for p in resp.result['projects']]
        self.assertIn(project['id'], pids)

        resp = self.get(url % {'values': tags[0],
                               'name': 'foo'})
        self.assertValidProjectListResponse(resp)
        self.assertEqual(len(resp.result['projects']), 0)

    def test_list_projects_filtering_by_parent_id(self):
        """Call ``GET /projects?parent_id={project_id}``."""
        projects = self._create_projects_hierarchy(hierarchy_size=2)

        # Add another child to projects[1] - it will be projects[3]
        new_ref = unit.new_project_ref(
            domain_id=self.domain_id,
            parent_id=projects[1]['project']['id'])
        resp = self.post('/projects',
                         body={'project': new_ref})
        self.assertValidProjectResponse(resp, new_ref)

        projects.append(resp.result)

        # Query for projects[0] immediate children - it will
        # be only projects[1]
        r = self.get(
            '/projects?parent_id=%(project_id)s' % {
                'project_id': projects[0]['project']['id']})
        self.assertValidProjectListResponse(r)

        projects_result = r.result['projects']
        expected_list = [projects[1]['project']]

        # projects[0] has projects[1] as child
        self.assertEqual(expected_list, projects_result)

        # Query for projects[1] immediate children - it will
        # be projects[2] and projects[3]
        r = self.get(
            '/projects?parent_id=%(project_id)s' % {
                'project_id': projects[1]['project']['id']})
        self.assertValidProjectListResponse(r)

        projects_result = r.result['projects']
        expected_list = [projects[2]['project'], projects[3]['project']]

        # projects[1] has projects[2] and projects[3] as children
        self.assertEqual(expected_list, projects_result)

        # Query for projects[2] immediate children - it will be an empty list
        r = self.get(
            '/projects?parent_id=%(project_id)s' % {
                'project_id': projects[2]['project']['id']})
        self.assertValidProjectListResponse(r)

        projects_result = r.result['projects']
        expected_list = []

        # projects[2] has no child, projects_result must be an empty list
        self.assertEqual(expected_list, projects_result)

    def test_create_hierarchical_project(self):
        """Call ``POST /projects``."""
        self._create_projects_hierarchy()

    def test_get_head_project(self):
        """Call ``GET & HEAD /projects/{project_id}``."""
        resource_url = '/projects/%(project_id)s' % {
            'project_id': self.project_id}
        r = self.get(resource_url)
        self.assertValidProjectResponse(r, self.project)
        self.head(resource_url, expected_status=http.client.OK)

    def test_get_project_with_parents_as_list_with_invalid_id(self):
        """Call ``GET /projects/{project_id}?parents_as_list``."""
        self.get('/projects/%(project_id)s?parents_as_list' % {
                 'project_id': None}, expected_status=http.client.NOT_FOUND)

        self.get('/projects/%(project_id)s?parents_as_list' % {
                 'project_id': uuid.uuid4().hex},
                 expected_status=http.client.NOT_FOUND)

    def test_get_project_with_subtree_as_list_with_invalid_id(self):
        """Call ``GET /projects/{project_id}?subtree_as_list``."""
        self.get('/projects/%(project_id)s?subtree_as_list' % {
                 'project_id': None}, expected_status=http.client.NOT_FOUND)

        self.get('/projects/%(project_id)s?subtree_as_list' % {
                 'project_id': uuid.uuid4().hex},
                 expected_status=http.client.NOT_FOUND)

    def test_get_project_with_parents_as_ids(self):
        """Call ``GET /projects/{project_id}?parents_as_ids``."""
        projects = self._create_projects_hierarchy(hierarchy_size=2)

        # Query for projects[2] parents_as_ids
        r = self.get(
            '/projects/%(project_id)s?parents_as_ids' % {
                'project_id': projects[2]['project']['id']})

        self.assertValidProjectResponse(r, projects[2]['project'])
        parents_as_ids = r.result['project']['parents']

        # Assert parents_as_ids is a structured dictionary correctly
        # representing the hierarchy. The request was made using projects[2]
        # id, hence its parents should be projects[1], projects[0] and the
        # is_domain_project, which is the root of the hierarchy. It should
        # have the following structure:
        # {
        #   projects[1]: {
        #       projects[0]: {
        #           is_domain_project: None
        #       }
        #   }
        # }
        is_domain_project_id = projects[0]['project']['domain_id']
        expected_dict = {
            projects[1]['project']['id']: {
                projects[0]['project']['id']: {is_domain_project_id: None}
            }
        }
        self.assertDictEqual(expected_dict, parents_as_ids)

        # Query for projects[0] parents_as_ids
        r = self.get(
            '/projects/%(project_id)s?parents_as_ids' % {
                'project_id': projects[0]['project']['id']})

        self.assertValidProjectResponse(r, projects[0]['project'])
        parents_as_ids = r.result['project']['parents']

        # projects[0] has only the project that acts as a domain as parent
        expected_dict = {
            is_domain_project_id: None
        }
        self.assertDictEqual(expected_dict, parents_as_ids)

        # Query for is_domain_project parents_as_ids
        r = self.get(
            '/projects/%(project_id)s?parents_as_ids' % {
                'project_id': is_domain_project_id})

        parents_as_ids = r.result['project']['parents']

        # the project that acts as a domain has no parents, parents_as_ids
        # must be None
        self.assertIsNone(parents_as_ids)

    def test_get_project_with_parents_as_list_with_full_access(self):
        """``GET /projects/{project_id}?parents_as_list`` with full access.

        Test plan:

        - Create 'parent', 'project' and 'subproject' projects;
        - Assign a user a role on each one of those projects;
        - Check that calling parents_as_list on 'subproject' returns both
          'project' and 'parent'.

        """
        # Create the project hierarchy
        parent, project, subproject = self._create_projects_hierarchy(2)

        # Assign a role for the user on all the created projects
        for proj in (parent, project, subproject):
            self.put(self.build_role_assignment_link(
                role_id=self.role_id, user_id=self.user_id,
                project_id=proj['project']['id']))

        # Make the API call
        r = self.get('/projects/%(project_id)s?parents_as_list' %
                     {'project_id': subproject['project']['id']})
        self.assertValidProjectResponse(r, subproject['project'])

        # Assert only 'project' and 'parent' are in the parents list
        self.assertIn(project, r.result['project']['parents'])
        self.assertIn(parent, r.result['project']['parents'])
        self.assertEqual(2, len(r.result['project']['parents']))

    def test_get_project_with_parents_as_list_with_partial_access(self):
        """``GET /projects/{project_id}?parents_as_list`` with partial access.

        Test plan:

        - Create 'parent', 'project' and 'subproject' projects;
        - Assign a user a role on 'parent' and 'subproject';
        - Check that calling parents_as_list on 'subproject' only returns
          'parent'.

        """
        # Create the project hierarchy
        parent, project, subproject = self._create_projects_hierarchy(2)

        # Assign a role for the user on parent and subproject
        for proj in (parent, subproject):
            self.put(self.build_role_assignment_link(
                role_id=self.role_id, user_id=self.user_id,
                project_id=proj['project']['id']))

        # Make the API call
        r = self.get('/projects/%(project_id)s?parents_as_list' %
                     {'project_id': subproject['project']['id']})
        self.assertValidProjectResponse(r, subproject['project'])

        # Assert only 'parent' is in the parents list
        self.assertIn(parent, r.result['project']['parents'])
        self.assertEqual(1, len(r.result['project']['parents']))

    def test_get_project_with_parents_as_list_and_parents_as_ids(self):
        """Attempt to list a project's parents as both a list and as IDs.

        This uses ``GET /projects/{project_id}?parents_as_list&parents_as_ids``
        which should fail with a Bad Request due to the conflicting query
        strings.

        """
        projects = self._create_projects_hierarchy(hierarchy_size=2)

        self.get(
            '/projects/%(project_id)s?parents_as_list&parents_as_ids' % {
                'project_id': projects[1]['project']['id']},
            expected_status=http.client.BAD_REQUEST)

    def test_get_project_with_include_limits(self):
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role_id
        )
        system_admin_token = self.get_system_scoped_token()

        parent, project, subproject = self._create_projects_hierarchy(2)
        # Assign a role for the user on all the created projects
        for proj in (parent, project, subproject):
            self.put(self.build_role_assignment_link(
                role_id=self.role_id, user_id=self.user_id,
                project_id=proj['project']['id']))
        # create a registered limit and three limits for each project.
        reg_limit = unit.new_registered_limit_ref(service_id=self.service_id,
                                                  region_id=self.region_id,
                                                  resource_name='volume')
        self.post(
            '/registered_limits',
            body={'registered_limits': [reg_limit]},
            token=system_admin_token,
            expected_status=http.client.CREATED)
        limit1 = unit.new_limit_ref(project_id=parent['project']['id'],
                                    service_id=self.service_id,
                                    region_id=self.region_id,
                                    resource_name='volume')
        limit2 = unit.new_limit_ref(project_id=project['project']['id'],
                                    service_id=self.service_id,
                                    region_id=self.region_id,
                                    resource_name='volume')
        limit3 = unit.new_limit_ref(project_id=subproject['project']['id'],
                                    service_id=self.service_id,
                                    region_id=self.region_id,
                                    resource_name='volume')
        self.post(
            '/limits',
            body={'limits': [limit1, limit2, limit3]},
            token=system_admin_token,
            expected_status=http.client.CREATED)
        # "include_limits" should work together with "parents_as_list" or
        # "subtree_as_list". Only using "include_limits" really does nothing.
        r = self.get('/projects/%(project_id)s?include_limits' %
                     {'project_id': subproject['project']['id']})

        self.assertNotIn('parents', r.result['project'])
        self.assertNotIn('subtree', r.result['project'])
        self.assertNotIn('limits', r.result['project'])

        # using "include_limits" with "parents_as_list"
        r = self.get('/projects/%(project_id)s?include_limits&parents_as_list'
                     % {'project_id': subproject['project']['id']})

        self.assertEqual(2, len(r.result['project']['parents']))
        for parent in r.result['project']['parents']:
            self.assertEqual(1, len(parent['project']['limits']))
            self.assertEqual(parent['project']['id'],
                             parent['project']['limits'][0]['project_id'])
            self.assertEqual(10,
                             parent['project']['limits'][0]['resource_limit'])

        # using "include_limits" with "subtree_as_list"
        r = self.get('/projects/%(project_id)s?include_limits&subtree_as_list'
                     % {'project_id': parent['project']['id']})

        self.assertEqual(2, len(r.result['project']['subtree']))
        for child in r.result['project']['subtree']:
            self.assertEqual(1, len(child['project']['limits']))
            self.assertEqual(child['project']['id'],
                             child['project']['limits'][0]['project_id'])
            self.assertEqual(10,
                             child['project']['limits'][0]['resource_limit'])

    def test_list_project_is_domain_filter(self):
        """Call ``GET /projects?is_domain=True/False``."""
        # Get the initial number of projects, both acting as a domain as well
        # as regular.
        r = self.get('/projects?is_domain=True', expected_status=200)
        initial_number_is_domain_true = len(r.result['projects'])
        r = self.get('/projects?is_domain=False', expected_status=200)
        initial_number_is_domain_false = len(r.result['projects'])

        # Add some more projects acting as domains
        new_is_domain_project = unit.new_project_ref(is_domain=True)
        new_is_domain_project = PROVIDERS.resource_api.create_project(
            new_is_domain_project['id'], new_is_domain_project)
        new_is_domain_project2 = unit.new_project_ref(is_domain=True)
        new_is_domain_project2 = PROVIDERS.resource_api.create_project(
            new_is_domain_project2['id'], new_is_domain_project2)
        number_is_domain_true = initial_number_is_domain_true + 2

        r = self.get('/projects?is_domain=True', expected_status=200)
        self.assertThat(r.result['projects'],
                        matchers.HasLength(number_is_domain_true))
        self.assertIn(new_is_domain_project['id'],
                      [p['id'] for p in r.result['projects']])
        self.assertIn(new_is_domain_project2['id'],
                      [p['id'] for p in r.result['projects']])

        # Now add a regular project
        new_regular_project = unit.new_project_ref(domain_id=self.domain_id)
        new_regular_project = PROVIDERS.resource_api.create_project(
            new_regular_project['id'], new_regular_project)
        number_is_domain_false = initial_number_is_domain_false + 1

        # Check we still have the same number of projects acting as domains
        r = self.get('/projects?is_domain=True', expected_status=200)
        self.assertThat(r.result['projects'],
                        matchers.HasLength(number_is_domain_true))

        # Check the number of regular projects is correct
        r = self.get('/projects?is_domain=False', expected_status=200)
        self.assertThat(r.result['projects'],
                        matchers.HasLength(number_is_domain_false))
        self.assertIn(new_regular_project['id'],
                      [p['id'] for p in r.result['projects']])

    def test_list_project_is_domain_filter_default(self):
        """Default project list should not see projects acting as domains."""
        # Get the initial count of regular projects
        r = self.get('/projects?is_domain=False', expected_status=200)
        number_is_domain_false = len(r.result['projects'])

        # Make sure we have at least one project acting as a domain
        new_is_domain_project = unit.new_project_ref(is_domain=True)
        new_is_domain_project = PROVIDERS.resource_api.create_project(
            new_is_domain_project['id'], new_is_domain_project)

        r = self.get('/projects', expected_status=200)
        self.assertThat(r.result['projects'],
                        matchers.HasLength(number_is_domain_false))
        self.assertNotIn(new_is_domain_project, r.result['projects'])

    def test_get_project_with_subtree_as_ids(self):
        """Call ``GET /projects/{project_id}?subtree_as_ids``.

        This test creates a more complex hierarchy to test if the structured
        dictionary returned by using the ``subtree_as_ids`` query param
        correctly represents the hierarchy.

        The hierarchy contains 5 projects with the following structure::

                                  +--A--+
                                  |     |
                               +--B--+  C
                               |     |
                               D     E


        """
        projects = self._create_projects_hierarchy(hierarchy_size=2)

        # Add another child to projects[0] - it will be projects[3]
        new_ref = unit.new_project_ref(
            domain_id=self.domain_id,
            parent_id=projects[0]['project']['id'])
        resp = self.post('/projects',
                         body={'project': new_ref})
        self.assertValidProjectResponse(resp, new_ref)
        projects.append(resp.result)

        # Add another child to projects[1] - it will be projects[4]
        new_ref = unit.new_project_ref(
            domain_id=self.domain_id,
            parent_id=projects[1]['project']['id'])
        resp = self.post('/projects',
                         body={'project': new_ref})
        self.assertValidProjectResponse(resp, new_ref)
        projects.append(resp.result)

        # Query for projects[0] subtree_as_ids
        r = self.get(
            '/projects/%(project_id)s?subtree_as_ids' % {
                'project_id': projects[0]['project']['id']})
        self.assertValidProjectResponse(r, projects[0]['project'])
        subtree_as_ids = r.result['project']['subtree']

        # The subtree hierarchy from projects[0] should have the following
        # structure:
        # {
        #   projects[1]: {
        #       projects[2]: None,
        #       projects[4]: None
        #   },
        #   projects[3]: None
        # }
        expected_dict = {
            projects[1]['project']['id']: {
                projects[2]['project']['id']: None,
                projects[4]['project']['id']: None
            },
            projects[3]['project']['id']: None
        }
        self.assertDictEqual(expected_dict, subtree_as_ids)

        # Now query for projects[1] subtree_as_ids
        r = self.get(
            '/projects/%(project_id)s?subtree_as_ids' % {
                'project_id': projects[1]['project']['id']})
        self.assertValidProjectResponse(r, projects[1]['project'])
        subtree_as_ids = r.result['project']['subtree']

        # The subtree hierarchy from projects[1] should have the following
        # structure:
        # {
        #   projects[2]: None,
        #   projects[4]: None
        # }
        expected_dict = {
            projects[2]['project']['id']: None,
            projects[4]['project']['id']: None
        }
        self.assertDictEqual(expected_dict, subtree_as_ids)

        # Now query for projects[3] subtree_as_ids
        r = self.get(
            '/projects/%(project_id)s?subtree_as_ids' % {
                'project_id': projects[3]['project']['id']})
        self.assertValidProjectResponse(r, projects[3]['project'])
        subtree_as_ids = r.result['project']['subtree']

        # projects[3] has no subtree, subtree_as_ids must be None
        self.assertIsNone(subtree_as_ids)

    def test_get_project_with_subtree_as_list_with_full_access(self):
        """``GET /projects/{project_id}?subtree_as_list`` with full access.

        Test plan:

        - Create 'parent', 'project' and 'subproject' projects;
        - Assign a user a role on each one of those projects;
        - Check that calling subtree_as_list on 'parent' returns both 'parent'
          and 'subproject'.

        """
        # Create the project hierarchy
        parent, project, subproject = self._create_projects_hierarchy(2)

        # Assign a role for the user on all the created projects
        for proj in (parent, project, subproject):
            self.put(self.build_role_assignment_link(
                role_id=self.role_id, user_id=self.user_id,
                project_id=proj['project']['id']))

        # Make the API call
        r = self.get('/projects/%(project_id)s?subtree_as_list' %
                     {'project_id': parent['project']['id']})
        self.assertValidProjectResponse(r, parent['project'])

        # Assert only 'project' and 'subproject' are in the subtree
        self.assertIn(project, r.result['project']['subtree'])
        self.assertIn(subproject, r.result['project']['subtree'])
        self.assertEqual(2, len(r.result['project']['subtree']))

    def test_get_project_with_subtree_as_list_with_partial_access(self):
        """``GET /projects/{project_id}?subtree_as_list`` with partial access.

        Test plan:

        - Create 'parent', 'project' and 'subproject' projects;
        - Assign a user a role on 'parent' and 'subproject';
        - Check that calling subtree_as_list on 'parent' returns 'subproject'.

        """
        # Create the project hierarchy
        parent, project, subproject = self._create_projects_hierarchy(2)

        # Assign a role for the user on parent and subproject
        for proj in (parent, subproject):
            self.put(self.build_role_assignment_link(
                role_id=self.role_id, user_id=self.user_id,
                project_id=proj['project']['id']))

        # Make the API call
        r = self.get('/projects/%(project_id)s?subtree_as_list' %
                     {'project_id': parent['project']['id']})
        self.assertValidProjectResponse(r, parent['project'])

        # Assert only 'subproject' is in the subtree
        self.assertIn(subproject, r.result['project']['subtree'])
        self.assertEqual(1, len(r.result['project']['subtree']))

    def test_get_project_with_subtree_as_list_and_subtree_as_ids(self):
        """Attempt to get a project subtree as both a list and as IDs.

        This uses ``GET /projects/{project_id}?subtree_as_list&subtree_as_ids``
        which should fail with a bad request due to the conflicting query
        strings.

        """
        projects = self._create_projects_hierarchy(hierarchy_size=2)

        self.get(
            '/projects/%(project_id)s?subtree_as_list&subtree_as_ids' % {
                'project_id': projects[1]['project']['id']},
            expected_status=http.client.BAD_REQUEST)

    def test_update_project(self):
        """Call ``PATCH /projects/{project_id}``."""
        ref = unit.new_project_ref(domain_id=self.domain_id,
                                   parent_id=self.project['parent_id'])
        del ref['id']
        r = self.patch(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id},
            body={'project': ref})
        self.assertValidProjectResponse(r, ref)

    def test_update_project_unsafe(self):
        """Call ``POST /projects/{project_id} with unsafe names``."""
        unsafe_name = 'i am not / safe'

        self.config_fixture.config(group='resource',
                                   project_name_url_safe='off')
        ref = unit.new_project_ref(name=unsafe_name,
                                   domain_id=self.domain_id,
                                   parent_id=self.project['parent_id'])
        del ref['id']
        self.patch(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id},
            body={'project': ref})

        unsafe_name = 'i am still not / safe'
        for config_setting in ['new', 'strict']:
            self.config_fixture.config(group='resource',
                                       project_name_url_safe=config_setting)
            ref = unit.new_project_ref(name=unsafe_name,
                                       domain_id=self.domain_id,
                                       parent_id=self.project['parent_id'])
            del ref['id']
            self.patch(
                '/projects/%(project_id)s' % {
                    'project_id': self.project_id},
                body={'project': ref},
                expected_status=http.client.BAD_REQUEST)

    def test_update_project_unsafe_default(self):
        """Check default for unsafe names for ``POST /projects``."""
        unsafe_name = 'i am not / safe'

        # By default, we should be able to create unsafe names
        ref = unit.new_project_ref(name=unsafe_name,
                                   domain_id=self.domain_id,
                                   parent_id=self.project['parent_id'])
        del ref['id']
        self.patch(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id},
            body={'project': ref})

    def test_update_project_domain_id(self):
        """Call ``PATCH /projects/{project_id}`` with domain_id.

        A projects's `domain_id` is immutable. Ensure that any attempts to
        update the `domain_id` of a project fails.
        """
        project = unit.new_project_ref(domain_id=self.domain['id'])
        project = PROVIDERS.resource_api.create_project(project['id'], project)
        project['domain_id'] = CONF.identity.default_domain_id
        self.patch('/projects/%(project_id)s' % {
            'project_id': project['id']},
            body={'project': project},
            expected_status=exception.ValidationError.code)

    def test_update_project_parent_id(self):
        """Call ``PATCH /projects/{project_id}``."""
        projects = self._create_projects_hierarchy()
        leaf_project = projects[1]['project']
        leaf_project['parent_id'] = None
        self.patch(
            '/projects/%(project_id)s' % {
                'project_id': leaf_project['id']},
            body={'project': leaf_project},
            expected_status=http.client.FORBIDDEN)

    def test_update_project_is_domain_not_allowed(self):
        """Call ``PATCH /projects/{project_id}`` with is_domain.

        The is_domain flag is immutable.
        """
        project = unit.new_project_ref(domain_id=self.domain['id'])
        resp = self.post('/projects',
                         body={'project': project})
        self.assertFalse(resp.result['project']['is_domain'])

        project['parent_id'] = resp.result['project']['parent_id']
        project['is_domain'] = True
        self.patch('/projects/%(project_id)s' % {
            'project_id': resp.result['project']['id']},
            body={'project': project},
            expected_status=http.client.BAD_REQUEST)

    def test_disable_leaf_project(self):
        """Call ``PATCH /projects/{project_id}``."""
        projects = self._create_projects_hierarchy()
        leaf_project = projects[1]['project']
        leaf_project['enabled'] = False
        r = self.patch(
            '/projects/%(project_id)s' % {
                'project_id': leaf_project['id']},
            body={'project': leaf_project})
        self.assertEqual(
            leaf_project['enabled'], r.result['project']['enabled'])

    def test_disable_not_leaf_project(self):
        """Call ``PATCH /projects/{project_id}``."""
        projects = self._create_projects_hierarchy()
        root_project = projects[0]['project']
        root_project['enabled'] = False
        self.patch(
            '/projects/%(project_id)s' % {
                'project_id': root_project['id']},
            body={'project': root_project},
            expected_status=http.client.FORBIDDEN)

    def test_delete_project(self):
        """Call ``DELETE /projects/{project_id}``.

        As well as making sure the delete succeeds, we ensure
        that any credentials that reference this projects are
        also deleted, while other credentials are unaffected.

        """
        credential = unit.new_credential_ref(user_id=self.user['id'],
                                             project_id=self.project_id)
        PROVIDERS.credential_api.create_credential(
            credential['id'], credential
        )

        # First check the credential for this project is present
        r = PROVIDERS.credential_api.get_credential(credential['id'])
        self.assertDictEqual(credential, r)
        # Create a second credential with a different project
        project2 = unit.new_project_ref(domain_id=self.domain['id'])
        PROVIDERS.resource_api.create_project(project2['id'], project2)
        credential2 = unit.new_credential_ref(user_id=self.user['id'],
                                              project_id=project2['id'])
        PROVIDERS.credential_api.create_credential(
            credential2['id'], credential2
        )

        # Now delete the project
        self.delete(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id})

        # Deleting the project should have deleted any credentials
        # that reference this project
        self.assertRaises(exception.CredentialNotFound,
                          PROVIDERS.credential_api.get_credential,
                          credential_id=credential['id'])
        # But the credential for project2 is unaffected
        r = PROVIDERS.credential_api.get_credential(credential2['id'])
        self.assertDictEqual(credential2, r)

    def test_delete_not_leaf_project(self):
        """Call ``DELETE /projects/{project_id}``."""
        projects = self._create_projects_hierarchy()
        self.delete(
            '/projects/%(project_id)s' % {
                'project_id': projects[0]['project']['id']},
            expected_status=http.client.FORBIDDEN)

    def test_create_project_with_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=10)
        ref = self.get(
            '/projects/%(project_id)s' % {
                'project_id': project['id']},
            expected_status=http.client.OK)
        self.assertIn('tags', ref.result['project'])
        for tag in tags:
            self.assertIn(tag, ref.result['project']['tags'])

    def test_update_project_with_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=9)
        tag = uuid.uuid4().hex
        project['tags'].append(tag)
        ref = self.patch(
            '/projects/%(project_id)s' % {
                'project_id': self.project_id},
            body={'project': {'tags': project['tags']}})
        self.assertIn(tag, ref.result['project']['tags'])

    def test_create_project_tag(self):
        tag = uuid.uuid4().hex
        url = '/projects/%(project_id)s/tags/%(value)s'
        self.put(url % {'project_id': self.project_id, 'value': tag},
                 expected_status=http.client.CREATED)
        self.get(url % {'project_id': self.project_id, 'value': tag},
                 expected_status=http.client.NO_CONTENT)

    def test_create_project_tag_is_case_insensitive(self):
        case_tags = ['case', 'CASE']
        for tag in case_tags:
            self.put(
                '/projects/%(project_id)s/tags/%(value)s' % {
                    'project_id': self.project_id,
                    'value': tag},
                expected_status=http.client.CREATED)
        resp = self.get('/projects/%(project_id)s' %
                        {'project_id': self.project_id},
                        expected_status=http.client.OK)
        for tag in case_tags:
            self.assertIn(tag, resp.result['project']['tags'])

    def test_get_single_project_tag(self):
        project, tags = self._create_project_and_tags()
        self.get(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': tags[0]},
            expected_status=http.client.NO_CONTENT)
        self.head(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': tags[0]},
            expected_status=http.client.NO_CONTENT)

    def test_get_project_tag_that_does_not_exist(self):
        project, _ = self._create_project_and_tags()
        self.get(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': uuid.uuid4().hex},
            expected_status=http.client.NOT_FOUND)

    def test_delete_project_tag(self):
        project, tags = self._create_project_and_tags()
        self.delete(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': tags[0]},
            expected_status=http.client.NO_CONTENT)
        self.get(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': self.project_id,
                'value': tags[0]},
            expected_status=http.client.NOT_FOUND)

    def test_delete_project_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        self.delete(
            '/projects/%(project_id)s/tags/' % {
                'project_id': project['id']},
            expected_status=http.client.NO_CONTENT)
        self.get(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': self.project_id,
                'value': tags[0]},
            expected_status=http.client.NOT_FOUND)
        resp = self.get(
            '/projects/%(project_id)s/tags/' % {
                'project_id': self.project_id},
            expected_status=http.client.OK)
        self.assertEqual(len(resp.result['tags']), 0)

    def test_create_project_tag_invalid_project_id(self):
        self.put(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': uuid.uuid4().hex,
                'value': uuid.uuid4().hex},
            expected_status=http.client.NOT_FOUND)

    def test_create_project_tag_unsafe_name(self):
        tag = uuid.uuid4().hex + ','
        self.put(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': self.project_id,
                'value': tag},
            expected_status=http.client.BAD_REQUEST)

    def test_create_project_tag_already_exists(self):
        project, tags = self._create_project_and_tags()
        self.put(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': tags[0]},
            expected_status=http.client.BAD_REQUEST)

    def test_create_project_tag_over_tag_limit(self):
        project, _ = self._create_project_and_tags(num_of_tags=80)
        self.put(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': uuid.uuid4().hex},
            expected_status=http.client.BAD_REQUEST)

    def test_create_project_tag_name_over_character_limit(self):
        tag = 'a' * 256
        self.put(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': self.project_id,
                'value': tag},
            expected_status=http.client.BAD_REQUEST)

    def test_delete_tag_invalid_project_id(self):
        self.delete(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': uuid.uuid4().hex,
                'value': uuid.uuid4().hex},
            expected_status=http.client.NOT_FOUND)

    def test_delete_project_tag_not_found(self):
        self.delete(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': self.project_id,
                'value': uuid.uuid4().hex},
            expected_status=http.client.NOT_FOUND)

    def test_list_project_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        resp = self.get(
            '/projects/%(project_id)s/tags' % {
                'project_id': project['id']},
            expected_status=http.client.OK)
        for tag in tags:
            self.assertIn(tag, resp.result['tags'])

    def test_check_if_project_tag_exists(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        self.head(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': tags[0]},
            expected_status=http.client.NO_CONTENT)

    def test_list_project_tags_for_project_with_no_tags(self):
        resp = self.get(
            '/projects/%(project_id)s/tags' % {
                'project_id': self.project_id},
            expected_status=http.client.OK)
        self.assertEqual([], resp.result['tags'])

    def test_check_project_with_no_tags(self):
        self.head(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': self.project_id,
                'value': uuid.uuid4().hex},
            expected_status=http.client.NOT_FOUND)

    def test_update_project_tags(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        resp = self.put(
            '/projects/%(project_id)s/tags' % {
                'project_id': project['id']},
            body={'tags': tags},
            expected_status=http.client.OK)
        self.assertIn(tags[1], resp.result['tags'])

    def test_update_project_tags_removes_previous_tags(self):
        tag = uuid.uuid4().hex
        project, tags = self._create_project_and_tags(num_of_tags=5)
        self.put(
            '/projects/%(project_id)s/tags/%(value)s' % {
                'project_id': project['id'],
                'value': tag},
            expected_status=http.client.CREATED)
        resp = self.put(
            '/projects/%(project_id)s/tags' % {
                'project_id': project['id']},
            body={'tags': tags},
            expected_status=http.client.OK)
        self.assertNotIn(tag, resp.result['tags'])
        self.assertIn(tags[1], resp.result['tags'])

    def test_update_project_tags_unsafe_names(self):
        project, tags = self._create_project_and_tags(num_of_tags=5)
        invalid_chars = [',', '/']
        for char in invalid_chars:
            tags[0] = uuid.uuid4().hex + char
            self.put(
                '/projects/%(project_id)s/tags' % {
                    'project_id': project['id']},
                body={'tags': tags},
                expected_status=http.client.BAD_REQUEST)

    def test_update_project_tags_with_too_many_tags(self):
        project, _ = self._create_project_and_tags()
        tags = [uuid.uuid4().hex for i in range(81)]
        tags.append(uuid.uuid4().hex)
        self.put(
            '/projects/%(project_id)s/tags' % {'project_id': project['id']},
            body={'tags': tags},
            expected_status=http.client.BAD_REQUEST)

    def test_list_projects_by_user_with_inherited_role(self):
        """Ensure the cache is invalidated when creating/deleting a project."""
        domain_ref = unit.new_domain_ref()
        resp = self.post('/domains', body={'domain': domain_ref})
        domain = resp.result['domain']

        user_ref = unit.new_user_ref(domain_id=self.domain_id)
        resp = self.post('/users', body={'user': user_ref})
        user = resp.result['user']

        role_ref = unit.new_role_ref()
        resp = self.post('/roles', body={'role': role_ref})
        role = resp.result['role']

        self.put('/OS-INHERIT/domains/%(domain_id)s/users/%(user_id)s/roles/'
                 '%(role_id)s/inherited_to_projects' % {
                     'domain_id': domain['id'],
                     'user_id': user['id'],
                     'role_id': role['id']})

        resp = self.get('/users/%(user)s/projects' % {'user': user['id']})
        self.assertValidProjectListResponse(resp)
        self.assertEqual([], resp.result['projects'])

        project_ref = unit.new_project_ref(domain_id=domain['id'])
        resp = self.post('/projects', body={'project': project_ref})
        project = resp.result['project']

        resp = self.get('/users/%(user)s/projects' % {'user': user['id']})
        self.assertValidProjectListResponse(resp)
        self.assertEqual(project['id'], resp.result['projects'][0]['id'])


class StrictTwoLevelLimitsResourceTestCase(ResourceTestCase):
    def setUp(self):
        super(StrictTwoLevelLimitsResourceTestCase, self).setUp()

    def config_overrides(self):
        super(StrictTwoLevelLimitsResourceTestCase, self).config_overrides()
        self.config_fixture.config(group='unified_limit',
                                   enforcement_model='strict_two_level')

    def _create_projects_hierarchy(self, hierarchy_size=1):
        if hierarchy_size > 1:
            self.skip_test_overrides(
                "Strict two level limit enforcement model doesn't allow the"
                "project tree depth > 2")
        return super(StrictTwoLevelLimitsResourceTestCase,
                     self)._create_projects_hierarchy(hierarchy_size)

    def test_create_hierarchical_project(self):
        projects = self._create_projects_hierarchy()

        # create grandchild project will fail.
        new_ref = unit.new_project_ref(
            domain_id=self.domain_id,
            parent_id=projects[1]['project']['id'])
        self.post('/projects',
                  body={'project': new_ref},
                  expected_status=http.client.FORBIDDEN)

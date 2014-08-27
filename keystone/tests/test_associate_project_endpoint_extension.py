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

import copy
import uuid

# NOTE(morganfainberg): import endpoint filter to populate the SQL model
from keystone.contrib import endpoint_filter  # flake8: noqa
from keystone.tests import test_v3


class TestExtensionCase(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'endpoint_filter'
    EXTENSION_TO_ADD = 'endpoint_filter_extension'

    def config_overrides(self):
        super(TestExtensionCase, self).config_overrides()
        self.config_fixture.config(
            group='catalog',
            driver='keystone.contrib.endpoint_filter.backends.catalog_sql.'
                   'EndpointFilterCatalog')

    def setUp(self):
        super(TestExtensionCase, self).setUp()
        self.default_request_url = (
            '/OS-EP-FILTER/projects/%(project_id)s'
            '/endpoints/%(endpoint_id)s' % {
                'project_id': self.default_domain_project_id,
                'endpoint_id': self.endpoint_id})


class EndpointFilterCRUDTestCase(TestExtensionCase):

    def test_create_endpoint_project_association(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Valid endpoint and project id test case.

        """
        self.put(self.default_request_url,
                 body='',
                 expected_status=204)

    def test_create_endpoint_project_association_with_invalid_project(self):
        """PUT OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid project id test case.

        """
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': uuid.uuid4().hex,
                     'endpoint_id': self.endpoint_id},
                 body='',
                 expected_status=404)

    def test_create_endpoint_project_association_with_invalid_endpoint(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid endpoint id test case.

        """
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': uuid.uuid4().hex},
                 body='',
                 expected_status=404)

    def test_create_endpoint_project_association_with_unexpected_body(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Unexpected body in request. The body should be ignored.

        """
        self.put(self.default_request_url,
                 body={'project_id': self.default_domain_project_id},
                 expected_status=204)

    def test_check_endpoint_project_association(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Valid project and endpoint id test case.

        """
        self.put(self.default_request_url,
                 body='',
                 expected_status=204)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': self.default_domain_project_id,
                      'endpoint_id': self.endpoint_id},
                  expected_status=204)

    def test_check_endpoint_project_association_with_invalid_project(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': uuid.uuid4().hex,
                      'endpoint_id': self.endpoint_id},
                  body='',
                  expected_status=404)

    def test_check_endpoint_project_association_with_invalid_endpoint(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': self.default_domain_project_id,
                      'endpoint_id': uuid.uuid4().hex},
                  body='',
                  expected_status=404)

    def test_list_endpoints_associated_with_valid_project(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoints

        Valid project and endpoint id test case.

        """
        self.put(self.default_request_url)
        resource_url = '/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
                       'project_id': self.default_domain_project_id}
        r = self.get(resource_url)
        self.assertValidEndpointListResponse(r, self.endpoint,
                                             resource_url=resource_url)

    def test_list_endpoints_associated_with_invalid_project(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoints

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        self.get('/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
                 'project_id': uuid.uuid4().hex},
                 body='',
                 expected_status=404)

    def test_list_projects_associated_with_endpoint(self):
        """GET /OS-EP-FILTER/endpoints/{endpoint_id}/projects

        Valid endpoint-project association test case.

        """
        self.put(self.default_request_url)
        resource_url = '/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' % {
                       'endpoint_id': self.endpoint_id}
        r = self.get(resource_url)
        self.assertValidProjectListResponse(r, self.default_domain_project,
                                            resource_url=resource_url)

    def test_list_projects_with_no_endpoint_project_association(self):
        """GET /OS-EP-FILTER/endpoints/{endpoint_id}/projects

        Valid endpoint id but no endpoint-project associations test case.

        """
        r = self.get('/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' %
                     {'endpoint_id': self.endpoint_id},
                     expected_status=200)
        self.assertValidProjectListResponse(r, expected_length=0)

    def test_list_projects_associated_with_invalid_endpoint(self):
        """GET /OS-EP-FILTER/endpoints/{endpoint_id}/projects

        Invalid endpoint id test case.

        """
        self.get('/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' %
                 {'endpoint_id': uuid.uuid4().hex},
                 expected_status=404)

    def test_remove_endpoint_project_association(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Valid project id and endpoint id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': self.default_domain_project_id,
                        'endpoint_id': self.endpoint_id},
                    expected_status=204)

    def test_remove_endpoint_project_association_with_invalid_project(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': uuid.uuid4().hex,
                        'endpoint_id': self.endpoint_id},
                    body='',
                    expected_status=404)

    def test_remove_endpoint_project_association_with_invalid_endpoint(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': self.default_domain_project_id,
                        'endpoint_id': uuid.uuid4().hex},
                    body='',
                    expected_status=404)

    def test_endpoint_project_association_cleanup_when_project_deleted(self):
        self.put(self.default_request_url)
        association_url = '/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' % {
            'endpoint_id': self.endpoint_id}
        r = self.get(association_url, expected_status=200)
        self.assertValidProjectListResponse(r, expected_length=1)

        self.delete('/projects/%(project_id)s' % {
            'project_id': self.default_domain_project_id})

        r = self.get(association_url, expected_status=200)
        self.assertValidProjectListResponse(r, expected_length=0)

    def test_endpoint_project_association_cleanup_when_endpoint_deleted(self):
        self.put(self.default_request_url)
        association_url = '/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
            'project_id': self.default_domain_project_id}
        r = self.get(association_url, expected_status=200)
        self.assertValidEndpointListResponse(r, expected_length=1)

        self.delete('/endpoints/%(endpoint_id)s' % {
            'endpoint_id': self.endpoint_id})

        r = self.get(association_url, expected_status=200)
        self.assertValidEndpointListResponse(r, expected_length=0)


class EndpointFilterTokenRequestTestCase(TestExtensionCase):

    def test_project_scoped_token_using_endpoint_filter(self):
        """Verify endpoints from project scoped token filtered.""" 
        # create a project to work with
        ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)

        # grant the user a role on the project
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'user_id': self.user['id'],
                'project_id': project['id'],
                'role_id': self.role['id']})

        # set the user's preferred project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body=body)
        self.assertValidUserResponse(r)

        # add one endpoint to the project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': project['id'],
                     'endpoint_id': self.endpoint_id},
                 body='',
                 expected_status=204)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=True,
            endpoint_filter=True,
            ep_filter_assoc=1)
        self.assertEqual(r.result['token']['project']['id'], project['id'])

    def test_default_scoped_token_using_endpoint_filter(self):
        """Verify endpoints from default scoped token filtered."""
        # add one endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
                 body='',
                 expected_status=204)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=True,
            endpoint_filter=True,
            ep_filter_assoc=1)
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])

    def test_project_scoped_token_with_no_catalog_using_endpoint_filter(self): 
        """Verify endpoint filter when project scoped token returns no catalog.

        Test that the project scoped token response is valid for a given
        endpoint-project association when no service catalog is returned.

        """
        # create a project to work with
        ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)

        # grant the user a role on the project
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'user_id': self.user['id'],
                'project_id': project['id'],
                'role_id': self.role['id']})

        # set the user's preferred project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body=body)
        self.assertValidUserResponse(r)

        # add one endpoint to the project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': project['id'],
                     'endpoint_id': self.endpoint_id},
                 body='',
                 expected_status=204)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=False,
            endpoint_filter=True,
            ep_filter_assoc=1)
        self.assertEqual(r.result['token']['project']['id'], project['id'])

    def test_default_scoped_token_with_no_catalog_using_endpoint_filter(self):
        """Verify endpoint filter when default scoped token returns no catalog.

        Test that the default project scoped token response is valid for a
        given endpoint-project association when no service catalog is returned.

        """
        # add one endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
                 body='',
                 expected_status=204)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=False,
            endpoint_filter=True,
            ep_filter_assoc=1)
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])

    def test_project_scoped_token_with_no_endpoint_project_association(self):
        """Verify endpoint filter when no endpoint-project association.

        Test that the project scoped token response is valid when there are
        no endpoint-project associations defined.

        """
        # create a project to work with
        ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': ref})
        project = self.assertValidProjectResponse(r, ref)

        # grant the user a role on the project
        self.put(
            '/projects/%(project_id)s/users/%(user_id)s/roles/%(role_id)s' % {
                'user_id': self.user['id'],
                'project_id': project['id'],
                'role_id': self.role['id']})

        # set the user's preferred project
        body = {'user': {'default_project_id': project['id']}}
        r = self.patch('/users/%(user_id)s' % {
            'user_id': self.user['id']},
            body=body)
        self.assertValidUserResponse(r)

        # attempt to authenticate without requesting a project
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=False,
            endpoint_filter=True)
        self.assertEqual(r.result['token']['project']['id'], project['id'])

    def test_default_scoped_token_with_no_endpoint_project_association(self):
        """Verify endpoint filter when no endpoint-project association.

        Test that the default project scoped token response is valid when
        there are no endpoint-project associations defined.
        
        """
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=False,
            endpoint_filter=True,)
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])

    def test_invalid_endpoint_project_association(self):
        """Verify an invalid endpoint-project association is handled."""
        # add first endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
                 body='',
                 expected_status=204)

        # create a second temporary endpoint
        self.endpoint_id2 = uuid.uuid4().hex
        self.endpoint2 = self.new_endpoint_ref(service_id=self.service_id)
        self.endpoint2['id'] = self.endpoint_id2
        self.catalog_api.create_endpoint(
            self.endpoint_id2,
            self.endpoint2.copy())

        # add second endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id2},
                 body='',
                 expected_status=204)

        # remove the temporary reference
        # this will create inconsistency in the endpoint filter table
        # which is fixed during the catalog creation for token request
        self.catalog_api.delete_endpoint(self.endpoint_id2)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=True,
            endpoint_filter=True,
            ep_filter_assoc=1)
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])

    def test_disabled_endpoint(self):
        """Test that a disabled endpoint is handled."""
        # Add an enabled endpoint to the default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
                 expected_status=204)

        # Add a disabled endpoint to the default project.

        # Create a disabled endpoint that's like the enabled one.
        disabled_endpoint_ref = copy.copy(self.endpoint)
        disabled_endpoint_id = uuid.uuid4().hex
        disabled_endpoint_ref.update({
            'id': disabled_endpoint_id,
            'enabled': False,
            'interface': 'internal'
        })
        self.catalog_api.create_endpoint(disabled_endpoint_id,
                                         disabled_endpoint_ref)

        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': disabled_endpoint_id},
                 expected_status=204)

        # Authenticate to get token with catalog
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)

        endpoints = r.result['token']['catalog'][0]['endpoints']
        endpoint_ids = [ep['id'] for ep in endpoints]
        self.assertEqual([self.endpoint_id], endpoint_ids)


class JsonHomeTests(TestExtensionCase, test_v3.JsonHomeTestMixin):
    JSON_HOME_DATA = {
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_projects': {
            'href-template': '/OS-EP-FILTER/endpoints/{endpoint_id}/projects',
            'href-vars': {
                'endpoint_id':
                'http://docs.openstack.org/api/openstack-identity/3/param/'
                'endpoint_id',
            },
        },
    }

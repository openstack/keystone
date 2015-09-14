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

from six.moves import http_client
from testtools import matchers

from keystone.tests.unit import test_v3


class TestExtensionCase(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'endpoint_filter'
    EXTENSION_TO_ADD = 'endpoint_filter_extension'

    def config_overrides(self):
        super(TestExtensionCase, self).config_overrides()
        self.config_fixture.config(
            group='catalog', driver='endpoint_filter.sql')

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
                 expected_status=204)

    def test_create_endpoint_project_association_with_invalid_project(self):
        """PUT OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid project id test case.

        """
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': uuid.uuid4().hex,
                     'endpoint_id': self.endpoint_id},
                 expected_status=http_client.NOT_FOUND)

    def test_create_endpoint_project_association_with_invalid_endpoint(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid endpoint id test case.

        """
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': uuid.uuid4().hex},
                 expected_status=http_client.NOT_FOUND)

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
                  expected_status=http_client.NOT_FOUND)

    def test_check_endpoint_project_association_with_invalid_endpoint(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': self.default_domain_project_id,
                      'endpoint_id': uuid.uuid4().hex},
                  expected_status=http_client.NOT_FOUND)

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
                 expected_status=http_client.NOT_FOUND)

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
                 expected_status=http_client.NOT_FOUND)

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
                    expected_status=http_client.NOT_FOUND)

    def test_remove_endpoint_project_association_with_invalid_endpoint(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': self.default_domain_project_id,
                        'endpoint_id': uuid.uuid4().hex},
                    expected_status=http_client.NOT_FOUND)

    def test_endpoint_project_association_cleanup_when_project_deleted(self):
        self.put(self.default_request_url)
        association_url = ('/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' %
                           {'endpoint_id': self.endpoint_id})
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

    def test_scoped_token_with_no_catalog_using_endpoint_filter(self):
        """Verify endpoint filter does not affect no catalog."""
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
                 expected_status=204)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=False)
        self.assertEqual(r.result['token']['project']['id'],
                         self.project['id'])

    def test_invalid_endpoint_project_association(self):
        """Verify an invalid endpoint-project association is handled."""
        # add first endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
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

    def test_multiple_endpoint_project_associations(self):

        def _create_an_endpoint():
            endpoint_ref = self.new_endpoint_ref(service_id=self.service_id)
            r = self.post('/endpoints', body={'endpoint': endpoint_ref})
            return r.result['endpoint']['id']

        # create three endpoints
        endpoint_id1 = _create_an_endpoint()
        endpoint_id2 = _create_an_endpoint()
        _create_an_endpoint()

        # only associate two endpoints with project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': endpoint_id1},
                 expected_status=204)
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': endpoint_id2},
                 expected_status=204)

        # there should be only two endpoints in token catalog
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=True,
            endpoint_filter=True,
            ep_filter_assoc=2)

    def test_get_auth_catalog_using_endpoint_filter(self):
        # add one endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id},
                 expected_status=204)

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        token_data = self.post('/auth/tokens', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            token_data,
            require_catalog=True,
            endpoint_filter=True,
            ep_filter_assoc=1)

        auth_catalog = self.get('/auth/catalog',
                                token=token_data.headers['X-Subject-Token'])
        self.assertEqual(token_data.result['token']['catalog'],
                         auth_catalog.result['catalog'])


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
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_groups': {
            'href': '/OS-EP-FILTER/endpoint_groups',
        },
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_group': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}',
            'href-vars': {
                'endpoint_group_id':
                'http://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_group_to_project_association': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}/projects/{project_id}',
            'href-vars': {
                'project_id':
                'http://docs.openstack.org/api/openstack-identity/3/param/'
                'project_id',
                'endpoint_group_id':
                'http://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/projects_associated_with_endpoint_group': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}/projects',
            'href-vars': {
                'endpoint_group_id':
                'http://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoints_in_endpoint_group': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}/endpoints',
            'href-vars': {
                'endpoint_group_id':
                'http://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'http://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/project_endpoint_groups': {
            'href-template': '/OS-EP-FILTER/projects/{project_id}/'
            'endpoint_groups',
            'href-vars': {
                'project_id':
                'http://docs.openstack.org/api/openstack-identity/3/param/'
                'project_id',
            },
        },
    }


class EndpointGroupCRUDTestCase(TestExtensionCase):

    DEFAULT_ENDPOINT_GROUP_BODY = {
        'endpoint_group': {
            'description': 'endpoint group description',
            'filters': {
                'interface': 'admin'
            },
            'name': 'endpoint_group_name'
        }
    }

    DEFAULT_ENDPOINT_GROUP_URL = '/OS-EP-FILTER/endpoint_groups'

    def test_create_endpoint_group(self):
        """POST /OS-EP-FILTER/endpoint_groups

        Valid endpoint group test case.

        """
        r = self.post(self.DEFAULT_ENDPOINT_GROUP_URL,
                      body=self.DEFAULT_ENDPOINT_GROUP_BODY)
        expected_filters = (self.DEFAULT_ENDPOINT_GROUP_BODY
                            ['endpoint_group']['filters'])
        expected_name = (self.DEFAULT_ENDPOINT_GROUP_BODY
                         ['endpoint_group']['name'])
        self.assertEqual(expected_filters,
                         r.result['endpoint_group']['filters'])
        self.assertEqual(expected_name, r.result['endpoint_group']['name'])
        self.assertThat(
            r.result['endpoint_group']['links']['self'],
            matchers.EndsWith(
                '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
                    'endpoint_group_id': r.result['endpoint_group']['id']}))

    def test_create_invalid_endpoint_group(self):
        """POST /OS-EP-FILTER/endpoint_groups

        Invalid endpoint group creation test case.

        """
        invalid_body = copy.deepcopy(self.DEFAULT_ENDPOINT_GROUP_BODY)
        invalid_body['endpoint_group']['filters'] = {'foobar': 'admin'}
        self.post(self.DEFAULT_ENDPOINT_GROUP_URL,
                  body=invalid_body,
                  expected_status=http_client.BAD_REQUEST)

    def test_get_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Valid endpoint group test case.

        """
        # create an endpoint group to work with
        response = self.post(self.DEFAULT_ENDPOINT_GROUP_URL,
                             body=self.DEFAULT_ENDPOINT_GROUP_BODY)
        endpoint_group_id = response.result['endpoint_group']['id']
        endpoint_group_filters = response.result['endpoint_group']['filters']
        endpoint_group_name = response.result['endpoint_group']['name']
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.get(url)
        self.assertEqual(endpoint_group_id,
                         response.result['endpoint_group']['id'])
        self.assertEqual(endpoint_group_filters,
                         response.result['endpoint_group']['filters'])
        self.assertEqual(endpoint_group_name,
                         response.result['endpoint_group']['name'])
        self.assertThat(response.result['endpoint_group']['links']['self'],
                        matchers.EndsWith(url))

    def test_get_invalid_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Invalid endpoint group test case.

        """
        endpoint_group_id = 'foobar'
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_check_endpoint_group(self):
        """HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

        Valid endpoint_group_id test case.

        """
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.head(url, expected_status=200)

    def test_check_invalid_endpoint_group(self):
        """HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}

        Invalid endpoint_group_id test case.

        """
        endpoint_group_id = 'foobar'
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.head(url, expected_status=http_client.NOT_FOUND)

    def test_patch_endpoint_group(self):
        """PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Valid endpoint group patch test case.

        """
        body = copy.deepcopy(self.DEFAULT_ENDPOINT_GROUP_BODY)
        body['endpoint_group']['filters'] = {'region_id': 'UK'}
        body['endpoint_group']['name'] = 'patch_test'
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        r = self.patch(url, body=body)
        self.assertEqual(endpoint_group_id,
                         r.result['endpoint_group']['id'])
        self.assertEqual(body['endpoint_group']['filters'],
                         r.result['endpoint_group']['filters'])
        self.assertThat(r.result['endpoint_group']['links']['self'],
                        matchers.EndsWith(url))

    def test_patch_nonexistent_endpoint_group(self):
        """PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Invalid endpoint group patch test case.

        """
        body = {
            'endpoint_group': {
                'name': 'patch_test'
            }
        }
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': 'ABC'}
        self.patch(url, body=body, expected_status=http_client.NOT_FOUND)

    def test_patch_invalid_endpoint_group(self):
        """PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Valid endpoint group patch test case.

        """
        body = {
            'endpoint_group': {
                'description': 'endpoint group description',
                'filters': {
                    'region': 'UK'
                },
                'name': 'patch_test'
            }
        }
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.patch(url, body=body, expected_status=http_client.BAD_REQUEST)

        # Perform a GET call to ensure that the content remains
        # the same (as DEFAULT_ENDPOINT_GROUP_BODY) after attempting to update
        # with an invalid filter
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        r = self.get(url)
        del r.result['endpoint_group']['id']
        del r.result['endpoint_group']['links']
        self.assertDictEqual(self.DEFAULT_ENDPOINT_GROUP_BODY, r.result)

    def test_delete_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Valid endpoint group test case.

        """
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.delete(url)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_delete_invalid_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}

        Invalid endpoint group test case.

        """
        endpoint_group_id = 'foobar'
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.delete(url, expected_status=http_client.NOT_FOUND)

    def test_add_endpoint_group_to_project(self):
        """Create a valid endpoint group and project association."""
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        self._create_endpoint_group_project_association(endpoint_group_id,
                                                        self.project_id)

    def test_add_endpoint_group_to_project_with_invalid_project_id(self):
        """Create an invalid endpoint group and project association."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # associate endpoint group with project
        project_id = uuid.uuid4().hex
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, project_id)
        self.put(url, expected_status=http_client.NOT_FOUND)

    def test_get_endpoint_group_in_project(self):
        """Test retrieving project endpoint group association."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # associate endpoint group with project
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.project_id)
        self.put(url)
        response = self.get(url)
        self.assertEqual(
            endpoint_group_id,
            response.result['project_endpoint_group']['endpoint_group_id'])
        self.assertEqual(
            self.project_id,
            response.result['project_endpoint_group']['project_id'])

    def test_get_invalid_endpoint_group_in_project(self):
        """Test retrieving project endpoint group association."""
        endpoint_group_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, project_id)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_list_endpoint_groups_in_project(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoint_groups."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # associate endpoint group with project
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.project_id)
        self.put(url)

        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoint_groups' %
               {'project_id': self.project_id})
        response = self.get(url)

        self.assertEqual(
            endpoint_group_id,
            response.result['endpoint_groups'][0]['id'])

    def test_list_endpoint_groups_in_invalid_project(self):
        """Test retrieving from invalid project."""
        project_id = uuid.uuid4().hex
        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoint_groups' %
               {'project_id': project_id})
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_empty_endpoint_groups_in_project(self):
        """Test when no endpoint groups associated with the project."""
        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoint_groups' %
               {'project_id': self.project_id})
        response = self.get(url)

        self.assertEqual(0, len(response.result['endpoint_groups']))

    def test_check_endpoint_group_to_project(self):
        """Test HEAD with a valid endpoint group and project association."""
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        self._create_endpoint_group_project_association(endpoint_group_id,
                                                        self.project_id)
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.project_id)
        self.head(url, expected_status=200)

    def test_check_endpoint_group_to_project_with_invalid_project_id(self):
        """Test HEAD with an invalid endpoint group and project association."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create an endpoint group to project association
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.project_id)
        self.put(url)

        # send a head request with an invalid project id
        project_id = uuid.uuid4().hex
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, project_id)
        self.head(url, expected_status=http_client.NOT_FOUND)

    def test_list_endpoint_groups(self):
        """GET /OS-EP-FILTER/endpoint_groups."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # recover all endpoint groups
        url = '/OS-EP-FILTER/endpoint_groups'
        r = self.get(url)
        self.assertNotEmpty(r.result['endpoint_groups'])
        self.assertEqual(endpoint_group_id,
                         r.result['endpoint_groups'][0].get('id'))

    def test_list_projects_associated_with_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}/projects

        Valid endpoint group test case.

        """
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # associate endpoint group with project
        self._create_endpoint_group_project_association(endpoint_group_id,
                                                        self.project_id)

        # recover list of projects associated with endpoint group
        url = ('/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s'
               '/projects' %
               {'endpoint_group_id': endpoint_group_id})
        self.get(url)

    def test_list_endpoints_associated_with_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}/endpoints

        Valid endpoint group test case.

        """
        # create a service
        service_ref = self.new_service_ref()
        response = self.post(
            '/services',
            body={'service': service_ref})

        service_id = response.result['service']['id']

        # create an endpoint
        endpoint_ref = self.new_endpoint_ref(service_id=service_id)
        response = self.post(
            '/endpoints',
            body={'endpoint': endpoint_ref})
        endpoint_id = response.result['endpoint']['id']

        # create an endpoint group
        body = copy.deepcopy(self.DEFAULT_ENDPOINT_GROUP_BODY)
        body['endpoint_group']['filters'] = {'service_id': service_id}
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, body)

        # create association
        self._create_endpoint_group_project_association(endpoint_group_id,
                                                        self.project_id)

        # recover list of endpoints associated with endpoint group
        url = ('/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s'
               '/endpoints' % {'endpoint_group_id': endpoint_group_id})
        r = self.get(url)
        self.assertNotEmpty(r.result['endpoints'])
        self.assertEqual(endpoint_id, r.result['endpoints'][0].get('id'))

    def test_list_endpoints_associated_with_project_endpoint_group(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoints

        Valid project, endpoint id, and endpoint group test case.

        """
        # create a temporary service
        service_ref = self.new_service_ref()
        response = self.post('/services', body={'service': service_ref})
        service_id2 = response.result['service']['id']

        # create additional endpoints
        self._create_endpoint_and_associations(
            self.default_domain_project_id, service_id2)
        self._create_endpoint_and_associations(
            self.default_domain_project_id)

        # create project and endpoint association with default endpoint:
        self.put(self.default_request_url)

        # create an endpoint group that contains a different endpoint
        body = copy.deepcopy(self.DEFAULT_ENDPOINT_GROUP_BODY)
        body['endpoint_group']['filters'] = {'service_id': service_id2}
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, body)

        # associate endpoint group with project
        self._create_endpoint_group_project_association(
            endpoint_group_id, self.default_domain_project_id)

        # Now get a list of the filtered endpoints
        endpoints_url = '/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
            'project_id': self.default_domain_project_id}
        r = self.get(endpoints_url)
        endpoints = self.assertValidEndpointListResponse(r)
        self.assertEqual(len(endpoints), 2)

        # Now remove project endpoint group association
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.default_domain_project_id)
        self.delete(url)

        # Now remove endpoint group
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.delete(url)

        r = self.get(endpoints_url)
        endpoints = self.assertValidEndpointListResponse(r)
        self.assertEqual(len(endpoints), 1)

    def test_endpoint_group_project_cleanup_with_project(self):
        # create endpoint group
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create new project and associate with endpoint_group
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': project_ref})
        project = self.assertValidProjectResponse(r, project_ref)
        url = self._get_project_endpoint_group_url(endpoint_group_id,
                                                   project['id'])
        self.put(url)

        # check that we can recover the project endpoint group association
        self.get(url)

        # Now delete the project and then try and retrieve the project
        # endpoint group association again
        self.delete('/projects/%(project_id)s' % {
            'project_id': project['id']})
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_endpoint_group_project_cleanup_with_endpoint_group(self):
        # create endpoint group
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create new project and associate with endpoint_group
        project_ref = self.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': project_ref})
        project = self.assertValidProjectResponse(r, project_ref)
        url = self._get_project_endpoint_group_url(endpoint_group_id,
                                                   project['id'])
        self.put(url)

        # check that we can recover the project endpoint group association
        self.get(url)

        # now remove the project endpoint group association
        self.delete(url)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_removing_an_endpoint_group_project(self):
        # create an endpoint group
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create an endpoint_group project
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.default_domain_project_id)
        self.put(url)

        # remove the endpoint group project
        self.delete(url)
        self.get(url, expected_status=http_client.NOT_FOUND)

    def test_remove_endpoint_group_with_project_association(self):
        # create an endpoint group
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create an endpoint_group project
        project_endpoint_group_url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.default_domain_project_id)
        self.put(project_endpoint_group_url)

        # remove endpoint group, the associated endpoint_group project will
        # be removed as well.
        endpoint_group_url = ('/OS-EP-FILTER/endpoint_groups/'
                              '%(endpoint_group_id)s'
                              % {'endpoint_group_id': endpoint_group_id})
        self.delete(endpoint_group_url)
        self.get(endpoint_group_url, expected_status=http_client.NOT_FOUND)
        self.get(project_endpoint_group_url,
                 expected_status=http_client.NOT_FOUND)

    def _create_valid_endpoint_group(self, url, body):
        r = self.post(url, body=body)
        return r.result['endpoint_group']['id']

    def _create_endpoint_group_project_association(self,
                                                   endpoint_group_id,
                                                   project_id):
        url = self._get_project_endpoint_group_url(endpoint_group_id,
                                                   project_id)
        self.put(url)

    def _get_project_endpoint_group_url(self,
                                        endpoint_group_id,
                                        project_id):
        return ('/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s'
                '/projects/%(project_id)s' %
                {'endpoint_group_id': endpoint_group_id,
                 'project_id': project_id})

    def _create_endpoint_and_associations(self, project_id, service_id=None):
        """Creates an endpoint associated with service and project."""
        if not service_id:
            # create a new service
            service_ref = self.new_service_ref()
            response = self.post(
                '/services', body={'service': service_ref})
            service_id = response.result['service']['id']

        # create endpoint
        endpoint_ref = self.new_endpoint_ref(service_id=service_id)
        response = self.post('/endpoints', body={'endpoint': endpoint_ref})
        endpoint = response.result['endpoint']

        # now add endpoint to project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': endpoint['id']})
        return endpoint

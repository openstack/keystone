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

import http.client
from testtools import matchers

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import test_v3

PROVIDERS = provider_api.ProviderAPIs


class EndpointFilterTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(EndpointFilterTestCase, self).setUp()
        self.default_request_url = (
            '/OS-EP-FILTER/projects/%(project_id)s'
            '/endpoints/%(endpoint_id)s' % {
                'project_id': self.default_domain_project_id,
                'endpoint_id': self.endpoint_id})


class EndpointFilterCRUDTestCase(EndpointFilterTestCase):

    def test_create_endpoint_project_association(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Valid endpoint and project id test case.

        """
        self.put(self.default_request_url)

    def test_create_endpoint_project_association_with_invalid_project(self):
        """PUT OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid project id test case.

        """
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': uuid.uuid4().hex,
                     'endpoint_id': self.endpoint_id},
                 expected_status=http.client.NOT_FOUND)

    def test_create_endpoint_project_association_with_invalid_endpoint(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid endpoint id test case.

        """
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': uuid.uuid4().hex},
                 expected_status=http.client.NOT_FOUND)

    def test_create_endpoint_project_association_with_unexpected_body(self):
        """PUT /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Unexpected body in request. The body should be ignored.

        """
        self.put(self.default_request_url,
                 body={'project_id': self.default_domain_project_id})

    def test_check_endpoint_project_association(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Valid project and endpoint id test case.

        """
        self.put(self.default_request_url)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': self.default_domain_project_id,
                      'endpoint_id': self.endpoint_id},
                  expected_status=http.client.NO_CONTENT)

    def test_check_endpoint_project_association_with_invalid_project(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': uuid.uuid4().hex,
                      'endpoint_id': self.endpoint_id},
                  expected_status=http.client.NOT_FOUND)

    def test_check_endpoint_project_association_with_invalid_endpoint(self):
        """HEAD /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.head('/OS-EP-FILTER/projects/%(project_id)s'
                  '/endpoints/%(endpoint_id)s' % {
                      'project_id': self.default_domain_project_id,
                      'endpoint_id': uuid.uuid4().hex},
                  expected_status=http.client.NOT_FOUND)

    def test_get_endpoint_project_association(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Valid project and endpoint id test case.

        """
        self.put(self.default_request_url)
        self.get('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': self.endpoint_id},
                 expected_status=http.client.NO_CONTENT)

    def test_get_endpoint_project_association_with_invalid_project(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        self.get('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': uuid.uuid4().hex,
                     'endpoint_id': self.endpoint_id},
                 expected_status=http.client.NOT_FOUND)

    def test_get_endpoint_project_association_with_invalid_endpoint(self):
        """GET /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.get('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': uuid.uuid4().hex},
                 expected_status=http.client.NOT_FOUND)

    def test_list_endpoints_associated_with_valid_project(self):
        """GET & HEAD /OS-EP-FILTER/projects/{project_id}/endpoints.

        Valid project and endpoint id test case.

        """
        self.put(self.default_request_url)
        resource_url = '/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
                       'project_id': self.default_domain_project_id}
        r = self.get(resource_url)
        self.assertValidEndpointListResponse(r, self.endpoint,
                                             resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_list_endpoints_associated_with_invalid_project(self):
        """GET & HEAD /OS-EP-FILTER/projects/{project_id}/endpoints.

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
            'project_id': uuid.uuid4().hex}
        )
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_list_projects_associated_with_endpoint(self):
        """GET & HEAD /OS-EP-FILTER/endpoints/{endpoint_id}/projects.

        Valid endpoint-project association test case.

        """
        self.put(self.default_request_url)
        resource_url = '/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' % {
                       'endpoint_id': self.endpoint_id}
        r = self.get(resource_url, expected_status=http.client.OK)
        self.assertValidProjectListResponse(r, self.default_domain_project,
                                            resource_url=resource_url)
        self.head(resource_url, expected_status=http.client.OK)

    def test_list_projects_with_no_endpoint_project_association(self):
        """GET & HEAD /OS-EP-FILTER/endpoints/{endpoint_id}/projects.

        Valid endpoint id but no endpoint-project associations test case.

        """
        url = (
            '/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' %
            {'endpoint_id': self.endpoint_id}
        )
        r = self.get(url, expected_status=http.client.OK)
        self.assertValidProjectListResponse(r, expected_length=0)
        self.head(url, expected_status=http.client.OK)

    def test_list_projects_associated_with_invalid_endpoint(self):
        """GET & HEAD /OS-EP-FILTER/endpoints/{endpoint_id}/projects.

        Invalid endpoint id test case.

        """
        url = (
            '/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' %
            {'endpoint_id': uuid.uuid4().hex}
        )
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_remove_endpoint_project_association(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Valid project id and endpoint id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': self.default_domain_project_id,
                        'endpoint_id': self.endpoint_id})

    def test_remove_endpoint_project_association_with_invalid_project(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid project id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': uuid.uuid4().hex,
                        'endpoint_id': self.endpoint_id},
                    expected_status=http.client.NOT_FOUND)

    def test_remove_endpoint_project_association_with_invalid_endpoint(self):
        """DELETE /OS-EP-FILTER/projects/{project_id}/endpoints/{endpoint_id}.

        Invalid endpoint id test case.

        """
        self.put(self.default_request_url)
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': self.default_domain_project_id,
                        'endpoint_id': uuid.uuid4().hex},
                    expected_status=http.client.NOT_FOUND)

    def test_endpoint_project_association_cleanup_when_project_deleted(self):
        self.put(self.default_request_url)
        association_url = ('/OS-EP-FILTER/endpoints/%(endpoint_id)s/projects' %
                           {'endpoint_id': self.endpoint_id})
        r = self.get(association_url)
        self.assertValidProjectListResponse(r, expected_length=1)

        self.delete('/projects/%(project_id)s' % {
            'project_id': self.default_domain_project_id})

        r = self.get(association_url)
        self.assertValidProjectListResponse(r, expected_length=0)

    def test_endpoint_project_association_cleanup_when_endpoint_deleted(self):
        self.put(self.default_request_url)
        association_url = '/OS-EP-FILTER/projects/%(project_id)s/endpoints' % {
            'project_id': self.default_domain_project_id}
        r = self.get(association_url)
        self.assertValidEndpointListResponse(r, expected_length=1)

        self.delete('/endpoints/%(endpoint_id)s' % {
            'endpoint_id': self.endpoint_id})

        r = self.get(association_url)
        self.assertValidEndpointListResponse(r, expected_length=0)

    @unit.skip_if_cache_disabled('catalog')
    def test_create_endpoint_project_association_invalidates_cache(self):
        # NOTE(davechen): create another endpoint which will be added to
        # default project, this should be done at first since
        # `create_endpoint` will also invalidate cache.
        endpoint_id2 = uuid.uuid4().hex
        endpoint2 = unit.new_endpoint_ref(service_id=self.service_id,
                                          region_id=self.region_id,
                                          interface='public',
                                          id=endpoint_id2)
        PROVIDERS.catalog_api.create_endpoint(endpoint_id2, endpoint2.copy())

        # create endpoint project association.
        self.put(self.default_request_url)

        # should get back only one endpoint that was just created.
        user_id = uuid.uuid4().hex
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        # there is only one endpoints associated with the default project.
        self.assertEqual(1, len(catalog[0]['endpoints']))
        self.assertEqual(self.endpoint_id, catalog[0]['endpoints'][0]['id'])

        # add the second endpoint to default project, bypassing
        # catalog_api API manager.
        PROVIDERS.catalog_api.driver.add_endpoint_to_project(
            endpoint_id2,
            self.default_domain_project_id)

        # but, we can just get back one endpoint from the cache, since the
        # catalog is pulled out from cache and its haven't been invalidated.
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertEqual(1, len(catalog[0]['endpoints']))

        # remove the endpoint2 from the default project, and add it again via
        # catalog_api API manager.
        PROVIDERS.catalog_api.driver.remove_endpoint_from_project(
            endpoint_id2,
            self.default_domain_project_id)

        # add second endpoint to default project, this can be done by calling
        # the catalog_api API manager directly but call the REST API
        # instead for consistency.
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': endpoint_id2})

        # should get back two endpoints since the cache has been
        # invalidated when the second endpoint was added to default project.
        catalog = self.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertEqual(2, len(catalog[0]['endpoints']))

        ep_id_list = [catalog[0]['endpoints'][0]['id'],
                      catalog[0]['endpoints'][1]['id']]
        self.assertCountEqual([self.endpoint_id, endpoint_id2], ep_id_list)

    @unit.skip_if_cache_disabled('catalog')
    def test_remove_endpoint_from_project_invalidates_cache(self):
        endpoint_id2 = uuid.uuid4().hex
        endpoint2 = unit.new_endpoint_ref(service_id=self.service_id,
                                          region_id=self.region_id,
                                          interface='public',
                                          id=endpoint_id2)
        PROVIDERS.catalog_api.create_endpoint(endpoint_id2, endpoint2.copy())
        # create endpoint project association.
        self.put(self.default_request_url)

        # add second endpoint to default project.
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.default_domain_project_id,
                     'endpoint_id': endpoint_id2})

        # should get back only one endpoint that was just created.
        user_id = uuid.uuid4().hex
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        # there are two endpoints associated with the default project.
        ep_id_list = [catalog[0]['endpoints'][0]['id'],
                      catalog[0]['endpoints'][1]['id']]
        self.assertEqual(2, len(catalog[0]['endpoints']))
        self.assertCountEqual([self.endpoint_id, endpoint_id2], ep_id_list)

        # remove the endpoint2 from the default project, bypassing
        # catalog_api API manager.
        PROVIDERS.catalog_api.driver.remove_endpoint_from_project(
            endpoint_id2,
            self.default_domain_project_id)

        # but, we can just still get back two endpoints from the cache,
        # since the catalog is pulled out from cache and its haven't
        # been invalidated.
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertEqual(2, len(catalog[0]['endpoints']))

        # add back the endpoint2 to the default project, and remove it by
        # catalog_api API manage.
        PROVIDERS.catalog_api.driver.add_endpoint_to_project(
            endpoint_id2,
            self.default_domain_project_id)

        # remove the endpoint2 from the default project, this can be done
        # by calling the catalog_api API manager directly but call
        # the REST API instead for consistency.
        self.delete('/OS-EP-FILTER/projects/%(project_id)s'
                    '/endpoints/%(endpoint_id)s' % {
                        'project_id': self.default_domain_project_id,
                        'endpoint_id': endpoint_id2})

        # should only get back one endpoint since the cache has been
        # invalidated after the endpoint project association was removed.
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertEqual(1, len(catalog[0]['endpoints']))
        self.assertEqual(self.endpoint_id, catalog[0]['endpoints'][0]['id'])


class EndpointFilterTokenRequestTestCase(EndpointFilterTestCase):

    def test_project_scoped_token_using_endpoint_filter(self):
        """Verify endpoints from project scoped token filtered."""
        # create a project to work with
        ref = unit.new_project_ref(domain_id=self.domain_id)
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
                     'endpoint_id': self.endpoint_id})

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
        self.assertEqual(project['id'], r.result['token']['project']['id'])

    def test_default_scoped_token_using_endpoint_filter(self):
        """Verify endpoints from default scoped token filtered."""
        # add one endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id})

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
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])

        # Ensure name of the service exists
        self.assertIn('name', r.result['token']['catalog'][0])

        # region and region_id should be the same in endpoints
        endpoint = r.result['token']['catalog'][0]['endpoints'][0]
        self.assertIn('region', endpoint)
        self.assertIn('region_id', endpoint)
        self.assertEqual(endpoint['region'], endpoint['region_id'])

    def test_scoped_token_with_no_catalog_using_endpoint_filter(self):
        """Verify endpoint filter does not affect no catalog."""
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id})

        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        r = self.post('/auth/tokens?nocatalog', body=auth_data)
        self.assertValidProjectScopedTokenResponse(
            r,
            require_catalog=False)
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])

    def test_invalid_endpoint_project_association(self):
        """Verify an invalid endpoint-project association is handled."""
        # add first endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id})

        # create a second temporary endpoint
        endpoint_id2 = uuid.uuid4().hex
        endpoint2 = unit.new_endpoint_ref(service_id=self.service_id,
                                          region_id=self.region_id,
                                          interface='public',
                                          id=endpoint_id2)
        PROVIDERS.catalog_api.create_endpoint(endpoint_id2, endpoint2.copy())

        # add second endpoint to default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': endpoint_id2})

        # remove the temporary reference
        # this will create inconsistency in the endpoint filter table
        # which is fixed during the catalog creation for token request
        PROVIDERS.catalog_api.delete_endpoint(endpoint_id2)

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
        self.assertEqual(self.project['id'],
                         r.result['token']['project']['id'])

    def test_disabled_endpoint(self):
        """Test that a disabled endpoint is handled."""
        # Add an enabled endpoint to the default project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': self.endpoint_id})

        # Add a disabled endpoint to the default project.

        # Create a disabled endpoint that's like the enabled one.
        disabled_endpoint_ref = copy.copy(self.endpoint)
        disabled_endpoint_id = uuid.uuid4().hex
        disabled_endpoint_ref.update({
            'id': disabled_endpoint_id,
            'enabled': False,
            'interface': 'internal'
        })
        PROVIDERS.catalog_api.create_endpoint(
            disabled_endpoint_id, disabled_endpoint_ref
        )

        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': disabled_endpoint_id})

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
            endpoint_ref = unit.new_endpoint_ref(service_id=self.service_id,
                                                 interface='public',
                                                 region_id=self.region_id)
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
                     'endpoint_id': endpoint_id1})
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': endpoint_id2})

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
                     'endpoint_id': self.endpoint_id})

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


class JsonHomeTests(EndpointFilterTestCase, test_v3.JsonHomeTestMixin):
    JSON_HOME_DATA = {
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_projects': {
            'href-template': '/OS-EP-FILTER/endpoints/{endpoint_id}/projects',
            'href-vars': {
                'endpoint_id':
                'https://docs.openstack.org/api/openstack-identity/3/param/'
                'endpoint_id',
            },
        },
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_groups': {
            'href': '/OS-EP-FILTER/endpoint_groups',
        },
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_group': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}',
            'href-vars': {
                'endpoint_group_id':
                'https://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoint_group_to_project_association': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}/projects/{project_id}',
            'href-vars': {
                'project_id':
                'https://docs.openstack.org/api/openstack-identity/3/param/'
                'project_id',
                'endpoint_group_id':
                'https://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/projects_associated_with_endpoint_group': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}/projects',
            'href-vars': {
                'endpoint_group_id':
                'https://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/endpoints_in_endpoint_group': {
            'href-template': '/OS-EP-FILTER/endpoint_groups/'
            '{endpoint_group_id}/endpoints',
            'href-vars': {
                'endpoint_group_id':
                'https://docs.openstack.org/api/openstack-identity/3/'
                'ext/OS-EP-FILTER/1.0/param/endpoint_group_id',
            },
        },
        'https://docs.openstack.org/api/openstack-identity/3/ext/OS-EP-FILTER/'
        '1.0/rel/project_endpoint_groups': {
            'href-template': '/OS-EP-FILTER/projects/{project_id}/'
            'endpoint_groups',
            'href-vars': {
                'project_id':
                'https://docs.openstack.org/api/openstack-identity/3/param/'
                'project_id',
            },
        },
    }


class EndpointGroupCRUDTestCase(EndpointFilterTestCase):

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
        """POST /OS-EP-FILTER/endpoint_groups.

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
        """POST /OS-EP-FILTER/endpoint_groups.

        Invalid endpoint group creation test case.

        """
        invalid_body = copy.deepcopy(self.DEFAULT_ENDPOINT_GROUP_BODY)
        invalid_body['endpoint_group']['filters'] = {'foobar': 'admin'}
        self.post(self.DEFAULT_ENDPOINT_GROUP_URL,
                  body=invalid_body,
                  expected_status=http.client.BAD_REQUEST)

    def test_get_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

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
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

        Invalid endpoint group test case.

        """
        endpoint_group_id = 'foobar'
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_check_endpoint_group(self):
        """HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}.

        Valid endpoint_group_id test case.

        """
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.head(url, expected_status=http.client.OK)

    def test_check_invalid_endpoint_group(self):
        """HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}.

        Invalid endpoint_group_id test case.

        """
        endpoint_group_id = 'foobar'
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_patch_endpoint_group(self):
        """PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

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
        """PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

        Invalid endpoint group patch test case.

        """
        body = {
            'endpoint_group': {
                'name': 'patch_test'
            }
        }
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': 'ABC'}
        self.patch(url, body=body, expected_status=http.client.NOT_FOUND)

    def test_patch_invalid_endpoint_group(self):
        """PATCH /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

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
        self.patch(url, body=body, expected_status=http.client.BAD_REQUEST)

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
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

        Valid endpoint group test case.

        """
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.delete(url)
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_delete_invalid_endpoint_group(self):
        """GET /OS-EP-FILTER/endpoint_groups/{endpoint_group}.

        Invalid endpoint group test case.

        """
        endpoint_group_id = 'foobar'
        url = '/OS-EP-FILTER/endpoint_groups/%(endpoint_group_id)s' % {
            'endpoint_group_id': endpoint_group_id}
        self.delete(url, expected_status=http.client.NOT_FOUND)

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
        self.put(url, expected_status=http.client.NOT_FOUND)

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
        self.get(url, expected_status=http.client.NOT_FOUND)

    def test_list_endpoint_groups_in_project(self):
        """GET & HEAD /OS-EP-FILTER/projects/{project_id}/endpoint_groups."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # associate endpoint group with project
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.project_id)
        self.put(url)

        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoint_groups' %
               {'project_id': self.project_id})
        response = self.get(url, expected_status=http.client.OK)

        self.assertEqual(
            endpoint_group_id,
            response.result['endpoint_groups'][0]['id'])

        self.head(url, expected_status=http.client.OK)

    def test_list_endpoint_groups_in_invalid_project(self):
        """Test retrieving from invalid project."""
        project_id = uuid.uuid4().hex
        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoint_groups' %
               {'project_id': project_id})
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_empty_endpoint_groups_in_project(self):
        """Test when no endpoint groups associated with the project."""
        url = ('/OS-EP-FILTER/projects/%(project_id)s/endpoint_groups' %
               {'project_id': self.project_id})
        response = self.get(url, expected_status=http.client.OK)

        self.assertEqual(0, len(response.result['endpoint_groups']))

        self.head(url, expected_status=http.client.OK)

    def test_check_endpoint_group_to_project(self):
        """Test HEAD with a valid endpoint group and project association."""
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)
        self._create_endpoint_group_project_association(endpoint_group_id,
                                                        self.project_id)
        url = self._get_project_endpoint_group_url(
            endpoint_group_id, self.project_id)
        self.head(url, expected_status=http.client.OK)

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
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_list_endpoint_groups(self):
        """GET & HEAD /OS-EP-FILTER/endpoint_groups."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # recover all endpoint groups
        url = '/OS-EP-FILTER/endpoint_groups'
        r = self.get(url, expected_status=http.client.OK)
        self.assertNotEmpty(r.result['endpoint_groups'])
        self.assertEqual(endpoint_group_id,
                         r.result['endpoint_groups'][0].get('id'))

        self.head(url, expected_status=http.client.OK)

    def test_list_endpoint_groups_by_name(self):
        """GET & HEAD /OS-EP-FILTER/endpoint_groups."""
        # create an endpoint group to work with
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # retrieve the single endpointgroup by name
        url = ('/OS-EP-FILTER/endpoint_groups?name=%(name)s' %
               {'name': 'endpoint_group_name'})
        r = self.get(url, expected_status=http.client.OK)
        self.assertNotEmpty(r.result['endpoint_groups'])
        self.assertEqual(1, len(r.result['endpoint_groups']))
        self.assertEqual(endpoint_group_id,
                         r.result['endpoint_groups'][0].get('id'))

        self.head(url, expected_status=http.client.OK)

        # try to retrieve a non existant one
        url = ('/OS-EP-FILTER/endpoint_groups?name=%(name)s' %
               {'name': 'fake'})
        r = self.get(url, expected_status=http.client.OK)
        self.assertEqual(0, len(r.result['endpoint_groups']))

    def test_list_projects_associated_with_endpoint_group(self):
        """GET & HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group}/projects.

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
        self.get(url, expected_status=http.client.OK)
        self.head(url, expected_status=http.client.OK)

    def test_list_endpoints_associated_with_endpoint_group(self):
        """GET & HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group}/endpoints.

        Valid endpoint group test case.

        """
        # create a service
        service_ref = unit.new_service_ref()
        response = self.post(
            '/services',
            body={'service': service_ref})

        service_id = response.result['service']['id']

        # create an endpoint
        endpoint_ref = unit.new_endpoint_ref(service_id=service_id,
                                             interface='public',
                                             region_id=self.region_id)
        response = self.post('/endpoints', body={'endpoint': endpoint_ref})
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
        r = self.get(url, expected_status=http.client.OK)
        self.assertNotEmpty(r.result['endpoints'])
        self.assertEqual(endpoint_id, r.result['endpoints'][0].get('id'))
        self.head(url, expected_status=http.client.OK)

    def test_list_endpoints_associated_with_project_endpoint_group(self):
        """GET & HEAD /OS-EP-FILTER/projects/{project_id}/endpoints.

        Valid project, endpoint id, and endpoint group test case.

        """
        # create a temporary service
        service_ref = unit.new_service_ref()
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
        r = self.get(endpoints_url, expected_status=http.client.OK)
        endpoints = self.assertValidEndpointListResponse(r)
        self.assertEqual(2, len(endpoints))
        self.head(endpoints_url, expected_status=http.client.OK)

        # Ensure catalog includes the endpoints from endpoint_group project
        # association, this is needed when a project scoped token is issued
        # and "endpoint_filter.sql" backend driver is in place.
        user_id = uuid.uuid4().hex
        catalog_list = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)
        self.assertEqual(2, len(catalog_list))

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
        self.assertEqual(1, len(endpoints))

        catalog_list = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)
        self.assertEqual(1, len(catalog_list))

    def test_endpoint_group_project_cleanup_with_project(self):
        # create endpoint group
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create new project and associate with endpoint_group
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': project_ref})
        project = self.assertValidProjectResponse(r, project_ref)
        url = self._get_project_endpoint_group_url(endpoint_group_id,
                                                   project['id'])
        self.put(url)

        # check that we can recover the project endpoint group association
        self.get(url, expected_status=http.client.OK)
        self.get(url, expected_status=http.client.OK)

        # Now delete the project and then try and retrieve the project
        # endpoint group association again
        self.delete('/projects/%(project_id)s' % {
            'project_id': project['id']})
        self.get(url, expected_status=http.client.NOT_FOUND)
        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_endpoint_group_project_cleanup_with_endpoint_group(self):
        # create endpoint group
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # create new project and associate with endpoint_group
        project_ref = unit.new_project_ref(domain_id=self.domain_id)
        r = self.post('/projects', body={'project': project_ref})
        project = self.assertValidProjectResponse(r, project_ref)
        url = self._get_project_endpoint_group_url(endpoint_group_id,
                                                   project['id'])
        self.put(url)

        # check that we can recover the project endpoint group association
        self.get(url)

        # now remove the project endpoint group association
        self.delete(url)
        self.get(url, expected_status=http.client.NOT_FOUND)

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
        self.get(url, expected_status=http.client.NOT_FOUND)

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
        self.get(endpoint_group_url, expected_status=http.client.NOT_FOUND)
        self.get(project_endpoint_group_url,
                 expected_status=http.client.NOT_FOUND)

    @unit.skip_if_cache_disabled('catalog')
    def test_add_endpoint_group_to_project_invalidates_catalog_cache(self):
        # create another endpoint with 'admin' interface which matches
        # 'filters' definition in endpoint group, then there should be two
        # endpoints returned when retrieving v3 catalog if cache works as
        # expected.
        # this should be done at first since `create_endpoint` will also
        # invalidate cache.
        endpoint_id2 = uuid.uuid4().hex
        endpoint2 = unit.new_endpoint_ref(service_id=self.service_id,
                                          region_id=self.region_id,
                                          interface='admin',
                                          id=endpoint_id2)
        PROVIDERS.catalog_api.create_endpoint(endpoint_id2, endpoint2)

        # create a project and endpoint association.
        self.put(self.default_request_url)

        # there is only one endpoint associated with the default project.
        user_id = uuid.uuid4().hex
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(1))

        # create an endpoint group.
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # add the endpoint group to default project, bypassing
        # catalog_api API manager.
        PROVIDERS.catalog_api.driver.add_endpoint_group_to_project(
            endpoint_group_id,
            self.default_domain_project_id)

        # can get back only one endpoint from the cache, since the catalog
        # is pulled out from cache.
        invalid_catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertThat(invalid_catalog[0]['endpoints'],
                        matchers.HasLength(1))
        self.assertEqual(catalog, invalid_catalog)

        # remove the endpoint group from default project, and add it again via
        # catalog_api API manager.
        PROVIDERS.catalog_api.driver.remove_endpoint_group_from_project(
            endpoint_group_id,
            self.default_domain_project_id)

        # add the endpoint group to default project.
        PROVIDERS.catalog_api.add_endpoint_group_to_project(
            endpoint_group_id,
            self.default_domain_project_id)

        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        # now, it will return 2 endpoints since the cache has been
        # invalidated.
        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(2))

        ep_id_list = [catalog[0]['endpoints'][0]['id'],
                      catalog[0]['endpoints'][1]['id']]
        self.assertCountEqual([self.endpoint_id, endpoint_id2], ep_id_list)

    @unit.skip_if_cache_disabled('catalog')
    def test_remove_endpoint_group_from_project_invalidates_cache(self):
        # create another endpoint with 'admin' interface which matches
        # 'filters' definition in endpoint group, then there should be two
        # endpoints returned when retrieving v3 catalog. But only one
        # endpoint will return after the endpoint group's deletion if cache
        # works as expected.
        # this should be done at first since `create_endpoint` will also
        # invalidate cache.
        endpoint_id2 = uuid.uuid4().hex
        endpoint2 = unit.new_endpoint_ref(service_id=self.service_id,
                                          region_id=self.region_id,
                                          interface='admin',
                                          id=endpoint_id2)
        PROVIDERS.catalog_api.create_endpoint(endpoint_id2, endpoint2)

        # create project and endpoint association.
        self.put(self.default_request_url)

        # create an endpoint group.
        endpoint_group_id = self._create_valid_endpoint_group(
            self.DEFAULT_ENDPOINT_GROUP_URL, self.DEFAULT_ENDPOINT_GROUP_BODY)

        # add the endpoint group to default project.
        PROVIDERS.catalog_api.add_endpoint_group_to_project(
            endpoint_group_id,
            self.default_domain_project_id)

        # should get back two endpoints, one from endpoint project
        # association, the other one is from endpoint_group project
        # association.
        user_id = uuid.uuid4().hex
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(2))

        ep_id_list = [catalog[0]['endpoints'][0]['id'],
                      catalog[0]['endpoints'][1]['id']]
        self.assertCountEqual([self.endpoint_id, endpoint_id2], ep_id_list)

        # remove endpoint_group project association, bypassing
        # catalog_api API manager.
        PROVIDERS.catalog_api.driver.remove_endpoint_group_from_project(
            endpoint_group_id,
            self.default_domain_project_id)

        # still get back two endpoints, since the catalog is pulled out
        # from cache and the cache haven't been invalidated.
        invalid_catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertThat(invalid_catalog[0]['endpoints'],
                        matchers.HasLength(2))
        self.assertEqual(catalog, invalid_catalog)

        # add back the endpoint_group project association and remove it from
        # manager.
        PROVIDERS.catalog_api.driver.add_endpoint_group_to_project(
            endpoint_group_id,
            self.default_domain_project_id)

        PROVIDERS.catalog_api.remove_endpoint_group_from_project(
            endpoint_group_id,
            self.default_domain_project_id)

        # should only get back one endpoint since the cache has been
        # invalidated after the endpoint_group project association was
        # removed.
        catalog = PROVIDERS.catalog_api.get_v3_catalog(
            user_id,
            self.default_domain_project_id)

        self.assertThat(catalog[0]['endpoints'], matchers.HasLength(1))
        self.assertEqual(self.endpoint_id, catalog[0]['endpoints'][0]['id'])

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
        """Create an endpoint associated with service and project."""
        if not service_id:
            # create a new service
            service_ref = unit.new_service_ref()
            response = self.post(
                '/services', body={'service': service_ref})
            service_id = response.result['service']['id']

        # create endpoint
        endpoint_ref = unit.new_endpoint_ref(service_id=service_id,
                                             interface='public',
                                             region_id=self.region_id)
        response = self.post('/endpoints', body={'endpoint': endpoint_ref})
        endpoint = response.result['endpoint']

        # now add endpoint to project
        self.put('/OS-EP-FILTER/projects/%(project_id)s'
                 '/endpoints/%(endpoint_id)s' % {
                     'project_id': self.project['id'],
                     'endpoint_id': endpoint['id']})
        return endpoint

# Copyright 2014 IBM Corp.
#
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

import http.client
from testtools import matchers

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import test_v3

PROVIDERS = provider_api.ProviderAPIs


class EndpointPolicyTestCase(test_v3.RestfulTestCase):
    """Test endpoint policy CRUD.

    In general, the controller layer of the endpoint policy extension is really
    just marshalling the data around the underlying manager calls. Given that
    the manager layer is tested in depth by the backend tests, the tests we
    execute here concentrate on ensuring we are correctly passing and
    presenting the data.

    """

    def setUp(self):
        super(EndpointPolicyTestCase, self).setUp()
        self.policy = unit.new_policy_ref()
        PROVIDERS.policy_api.create_policy(self.policy['id'], self.policy)
        self.service = unit.new_service_ref()
        PROVIDERS.catalog_api.create_service(self.service['id'], self.service)
        self.endpoint = unit.new_endpoint_ref(self.service['id'], enabled=True,
                                              interface='public',
                                              region_id=self.region_id)
        PROVIDERS.catalog_api.create_endpoint(
            self.endpoint['id'], self.endpoint
        )
        self.region = unit.new_region_ref()
        PROVIDERS.catalog_api.create_region(self.region)

    def assert_head_and_get_return_same_response(self, url, expected_status):
        self.get(url, expected_status=expected_status)
        self.head(url, expected_status=expected_status)

    # endpoint policy crud tests
    def _crud_test(self, url):
        # Test when the resource does not exist also ensures
        # that there is not a false negative after creation.

        self.assert_head_and_get_return_same_response(
            url,
            expected_status=http.client.NOT_FOUND)

        self.put(url)

        # test that the new resource is accessible.
        self.assert_head_and_get_return_same_response(
            url,
            expected_status=http.client.NO_CONTENT)

        self.delete(url)

        # test that the deleted resource is no longer accessible
        self.assert_head_and_get_return_same_response(
            url,
            expected_status=http.client.NOT_FOUND)

    def test_crud_for_policy_for_explicit_endpoint(self):
        """PUT, HEAD and DELETE for explicit endpoint policy."""
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/endpoints/%(endpoint_id)s') % {
                   'policy_id': self.policy['id'],
                   'endpoint_id': self.endpoint['id']}
        self._crud_test(url)

    def test_crud_for_policy_for_service(self):
        """PUT, HEAD and DELETE for service endpoint policy."""
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/services/%(service_id)s') % {
                   'policy_id': self.policy['id'],
                   'service_id': self.service['id']}
        self._crud_test(url)

    def test_crud_for_policy_for_region_and_service(self):
        """PUT, HEAD and DELETE for region and service endpoint policy."""
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/services/%(service_id)s/regions/%(region_id)s') % {
                   'policy_id': self.policy['id'],
                   'service_id': self.service['id'],
                   'region_id': self.region['id']}
        self._crud_test(url)

    def test_get_policy_for_endpoint(self):
        """GET /endpoints/{endpoint_id}/policy."""
        self.put('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
                 '/endpoints/%(endpoint_id)s' % {
                     'policy_id': self.policy['id'],
                     'endpoint_id': self.endpoint['id']})

        self.head('/endpoints/%(endpoint_id)s/OS-ENDPOINT-POLICY'
                  '/policy' % {
                      'endpoint_id': self.endpoint['id']},
                  expected_status=http.client.OK)

        r = self.get('/endpoints/%(endpoint_id)s/OS-ENDPOINT-POLICY'
                     '/policy' % {
                         'endpoint_id': self.endpoint['id']})
        self.assertValidPolicyResponse(r, ref=self.policy)

    def test_list_endpoints_for_policy(self):
        """GET & HEAD /policies/%(policy_id}/endpoints."""
        url = (
            '/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
            '/endpoints' % {'policy_id': self.policy['id']}
        )
        self.put(url + '/' + self.endpoint['id'])
        r = self.get(url)
        self.assertValidEndpointListResponse(r, ref=self.endpoint)
        self.assertThat(r.result.get('endpoints'), matchers.HasLength(1))
        self.head(url, expected_status=http.client.OK)

    def test_endpoint_association_cleanup_when_endpoint_deleted(self):
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/endpoints/%(endpoint_id)s') % {
                   'policy_id': self.policy['id'],
                   'endpoint_id': self.endpoint['id']}

        self.put(url)
        self.head(url)

        self.delete('/endpoints/%(endpoint_id)s' % {
            'endpoint_id': self.endpoint['id']})

        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_region_service_association_cleanup_when_region_deleted(self):
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/services/%(service_id)s/regions/%(region_id)s') % {
                   'policy_id': self.policy['id'],
                   'service_id': self.service['id'],
                   'region_id': self.region['id']}

        self.put(url)
        self.head(url)

        self.delete('/regions/%(region_id)s' % {
            'region_id': self.region['id']})

        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_region_service_association_cleanup_when_service_deleted(self):
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/services/%(service_id)s/regions/%(region_id)s') % {
                   'policy_id': self.policy['id'],
                   'service_id': self.service['id'],
                   'region_id': self.region['id']}

        self.put(url)
        self.head(url)

        self.delete('/services/%(service_id)s' % {
            'service_id': self.service['id']})

        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_service_association_cleanup_when_service_deleted(self):
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/services/%(service_id)s') % {
                   'policy_id': self.policy['id'],
                   'service_id': self.service['id']}

        self.put(url)
        self.get(url, expected_status=http.client.NO_CONTENT)

        self.delete('/policies/%(policy_id)s' % {
            'policy_id': self.policy['id']})

        self.head(url, expected_status=http.client.NOT_FOUND)

    def test_service_association_cleanup_when_policy_deleted(self):
        url = ('/policies/%(policy_id)s/OS-ENDPOINT-POLICY'
               '/services/%(service_id)s') % {
                   'policy_id': self.policy['id'],
                   'service_id': self.service['id']}

        self.put(url)
        self.get(url, expected_status=http.client.NO_CONTENT)

        self.delete('/services/%(service_id)s' % {
            'service_id': self.service['id']})

        self.head(url, expected_status=http.client.NOT_FOUND)


class JsonHomeTests(test_v3.JsonHomeTestMixin):
    EXTENSION_LOCATION = ('https://docs.openstack.org/api/openstack-identity/3'
                          '/ext/OS-ENDPOINT-POLICY/1.0/rel')
    PARAM_LOCATION = ('https://docs.openstack.org/api/openstack-identity/3/'
                      'param')

    JSON_HOME_DATA = {
        EXTENSION_LOCATION + '/endpoint_policy': {
            'href-template': '/endpoints/{endpoint_id}/OS-ENDPOINT-POLICY/'
                             'policy',
            'href-vars': {
                'endpoint_id': PARAM_LOCATION + '/endpoint_id',
            },
        },
        EXTENSION_LOCATION + '/policy_endpoints': {
            'href-template': '/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                             'endpoints',
            'href-vars': {
                'policy_id': PARAM_LOCATION + '/policy_id',
            },
        },
        EXTENSION_LOCATION + '/endpoint_policy_association': {
            'href-template': '/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                             'endpoints/{endpoint_id}',
            'href-vars': {
                'policy_id': PARAM_LOCATION + '/policy_id',
                'endpoint_id': PARAM_LOCATION + '/endpoint_id',
            },
        },
        EXTENSION_LOCATION + '/service_policy_association': {
            'href-template': '/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                             'services/{service_id}',
            'href-vars': {
                'policy_id': PARAM_LOCATION + '/policy_id',
                'service_id': PARAM_LOCATION + '/service_id',
            },
        },
        EXTENSION_LOCATION + '/region_and_service_policy_association': {
            'href-template': '/policies/{policy_id}/OS-ENDPOINT-POLICY/'
                             'services/{service_id}/regions/{region_id}',
            'href-vars': {
                'policy_id': PARAM_LOCATION + '/policy_id',
                'service_id': PARAM_LOCATION + '/service_id',
                'region_id': PARAM_LOCATION + '/region_id',
            },
        },
    }

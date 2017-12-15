# Copyright 2018 Huawei
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

from six.moves import http_client
import uuid

from keystone.common import provider_api
from keystone.tests import unit
from keystone.tests.unit import test_v3
from keystone.tests.unit import utils as test_utils

PROVIDERS = provider_api.ProviderAPIs


class RegisteredLimitsTestCase(test_v3.RestfulTestCase):
    """Test registered_limits CRUD."""

    def setUp(self):
        super(RegisteredLimitsTestCase, self).setUp()

        # There is already a sample service and region created from
        # load_sample_data() but we're going to create another service and
        # region for specific testing purposes.
        response = self.post('/regions', body={'region': {}})
        self.region2 = response.json_body['region']
        self.region_id2 = self.region2['id']

        service_ref = {'service': {
            'name': uuid.uuid4().hex,
            'enabled': True,
            'type': 'type2'}}
        response = self.post('/services', body=service_ref)
        self.service2 = response.json_body['service']
        self.service_id2 = self.service2['id']

    def test_create_registered_limit(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        registered_limits = r.result['registered_limits']
        for key in ['service_id', 'region_id', 'resource_name',
                    'default_limit']:
            self.assertEqual(registered_limits[0][key], ref[key])

    def test_create_registered_limit_without_region(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        registered_limits = r.result['registered_limits']
        for key in ['service_id', 'resource_name', 'default_limit']:
            self.assertEqual(registered_limits[0][key], ref[key])
        self.assertIsNone(registered_limits[0].get('region_id'))

    def test_create_multi_registered_limit(self):
        ref1 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id,
                                             resource_name='volume')
        ref2 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             resource_name='snapshot')
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        registered_limits = r.result['registered_limits']
        for key in ['service_id', 'resource_name', 'default_limit']:
            self.assertEqual(registered_limits[0][key], ref1[key])
            self.assertEqual(registered_limits[1][key], ref2[key])
        self.assertEqual(registered_limits[0]['region_id'], ref1['region_id'])
        self.assertIsNone(registered_limits[1].get('region_id'))

    def test_create_registered_limit_with_invalid_input(self):
        ref1 = unit.new_registered_limit_ref()
        ref2 = unit.new_registered_limit_ref(default_limit='not_int')
        ref3 = unit.new_registered_limit_ref(resource_name=123)
        ref4 = unit.new_registered_limit_ref(region_id='fake_region')
        for input_limit in [ref1, ref2, ref3, ref4]:
            self.post(
                '/registered_limits',
                body={'registered_limits': [input_limit]},
                expected_status=http_client.BAD_REQUEST)

    def test_create_registered_limit_duplicate(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id)
        self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CONFLICT)

    def test_update_registered_limit(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id,
                                            resource_name='volume',
                                            default_limit=10)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        update_ref = {
            'id': r.result['registered_limits'][0]['id'],
            'service_id': self.service_id2,
            'region_id': self.region_id2,
            'resource_name': 'snapshot',
            'default_limit': 5
        }
        r = self.put(
            '/registered_limits',
            body={'registered_limits': [update_ref]},
            expected_status=http_client.OK)
        new_registered_limits = r.result['registered_limits'][0]

        self.assertEqual(new_registered_limits['service_id'], self.service_id2)
        self.assertEqual(new_registered_limits['region_id'], self.region_id2)
        self.assertEqual(new_registered_limits['resource_name'], 'snapshot')
        self.assertEqual(new_registered_limits['default_limit'], 5)

    def test_update_multi_registered_limit(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id,
                                            resource_name='volume',
                                            default_limit=10)
        ref2 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id,
                                             resource_name='snapshot',
                                             default_limit=10)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref, ref2]},
            expected_status=http_client.CREATED)
        update_ref = {
            'id': r.result['registered_limits'][0]['id'],
            'service_id': self.service_id2,
            'region_id': self.region_id2,
            'resource_name': 'snapshot',
            'default_limit': 5
        }
        update_ref2 = {
            'id': r.result['registered_limits'][1]['id'],
            'service_id': self.service_id2,
            'region_id': self.region_id2,
            'resource_name': 'volume',
            'default_limit': 5
        }
        r = self.put(
            '/registered_limits',
            body={'registered_limits': [update_ref, update_ref2]},
            expected_status=http_client.OK)
        new_registered_limits = r.result['registered_limits']
        for key in ['id', 'service_id', 'region_id', 'resource_name',
                    'default_limit']:
            self.assertEqual(new_registered_limits[0][key], update_ref[key])
            self.assertEqual(new_registered_limits[1][key], update_ref2[key])

    def test_update_registered_limit_not_found(self):
        update_ref = {
            'id': uuid.uuid4().hex,
            'service_id': self.service_id,
            'region_id': self.region_id,
            'resource_name': 'snapshot',
            'default_limit': 5
        }
        self.put(
            '/registered_limits',
            body={'registered_limits': [update_ref]},
            expected_status=http_client.NOT_FOUND)

    def test_update_registered_limit_with_invalid_input(self):
        update_ref1 = unit.new_registered_limit_ref(id=uuid.uuid4().hex,
                                                    service_id='fake_id')
        update_ref2 = unit.new_registered_limit_ref(id=uuid.uuid4().hex,
                                                    default_limit='not_int')
        update_ref3 = unit.new_registered_limit_ref(id=uuid.uuid4().hex,
                                                    resource_name=123)
        update_ref4 = unit.new_registered_limit_ref(id=uuid.uuid4().hex,
                                                    region_id='fake_region')
        for input_limit in [update_ref1, update_ref2, update_ref3,
                            update_ref4]:
            self.put(
                '/registered_limits',
                body={'registered_limits': [input_limit]},
                expected_status=http_client.BAD_REQUEST)

    @test_utils.wip("Skipped until Bug 1744195 is resolved")
    def test_update_registered_limit_with_referenced_limit(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id,
                                            resource_name='volume',
                                            default_limit=10)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume')
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        update_ref = {
            'id': r.result['registered_limits'][0]['id'],
            'service_id': self.service_id2,
            'region_id': self.region_id2,
            'resource_name': 'snapshot',
            'default_limit': 5
        }
        self.put(
            '/registered_limits',
            body={'registered_limits': [update_ref]},
            expected_status=http_client.FORBIDDEN)

    def test_list_registered_limit(self):
        r = self.get(
            '/registered_limits',
            expected_status=http_client.OK)
        self.assertEqual([], r.result.get('registered_limits'))

        ref1 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             resource_name='test_resource',
                                             region_id=self.region_id)
        ref2 = unit.new_registered_limit_ref(service_id=self.service_id2,
                                             resource_name='test_resource',
                                             region_id=self.region_id2)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['registered_limits'][0]['id']
        r = self.get(
            '/registered_limits',
            expected_status=http_client.OK)
        registered_limits = r.result['registered_limits']
        self.assertEqual(len(registered_limits), 2)
        for key in ['service_id', 'region_id', 'resource_name',
                    'default_limit']:
            if registered_limits[0]['id'] == id1:
                self.assertEqual(registered_limits[0][key], ref1[key])
                self.assertEqual(registered_limits[1][key], ref2[key])
                break
            self.assertEqual(registered_limits[1][key], ref1[key])
            self.assertEqual(registered_limits[0][key], ref2[key])

        r = self.get(
            '/registered_limits?service_id=%s' % self.service_id,
            expected_status=http_client.OK)
        registered_limits = r.result['registered_limits']
        self.assertEqual(len(registered_limits), 1)
        for key in ['service_id', 'region_id', 'resource_name',
                    'default_limit']:
            self.assertEqual(registered_limits[0][key], ref1[key])

        r = self.get(
            '/registered_limits?region_id=%s' % self.region_id2,
            expected_status=http_client.OK)
        registered_limits = r.result['registered_limits']
        self.assertEqual(len(registered_limits), 1)
        for key in ['service_id', 'region_id', 'resource_name',
                    'default_limit']:
            self.assertEqual(registered_limits[0][key], ref2[key])

        r = self.get(
            '/registered_limits?resource_name=test_resource',
            expected_status=http_client.OK)
        registered_limits = r.result['registered_limits']
        self.assertEqual(len(registered_limits), 2)

    def test_show_registered_limit(self):
        ref1 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id)
        ref2 = unit.new_registered_limit_ref(service_id=self.service_id2,
                                             region_id=self.region_id2)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['registered_limits'][0]['id']
        self.get(
            '/registered_limits/fake_id',
            expected_status=http_client.NOT_FOUND)
        r = self.get(
            '/registered_limits/%s' % id1,
            expected_status=http_client.OK)
        registered_limit = r.result['registered_limit']
        for key in ['service_id', 'region_id', 'resource_name',
                    'default_limit']:
            self.assertEqual(registered_limit[key], ref1[key])

    def test_delete_registered_limit(self):
        ref1 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id)
        ref2 = unit.new_registered_limit_ref(service_id=self.service_id2,
                                             region_id=self.region_id2)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['registered_limits'][0]['id']
        self.delete('/registered_limits/%s' % id1,
                    expected_status=http_client.NO_CONTENT)
        self.delete('/registered_limits/fake_id',
                    expected_status=http_client.NOT_FOUND)
        r = self.get(
            '/registered_limits',
            expected_status=http_client.OK)
        registered_limits = r.result['registered_limits']
        self.assertEqual(len(registered_limits), 1)

    @test_utils.wip("Skipped until Bug 1744195 is resolved")
    def test_delete_registered_limit_with_referenced_limit(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id,
                                            resource_name='volume',
                                            default_limit=10)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume')
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        id = r.result['registered_limits'][0]['id']
        self.delete('/registered_limits/%s' % id,
                    expected_status=http_client.FORBIDDEN)


class LimitsTestCase(test_v3.RestfulTestCase):
    """Test limits CRUD."""

    def setUp(self):
        super(LimitsTestCase, self).setUp()

        # There is already a sample service and region created from
        # load_sample_data() but we're going to create another service and
        # region for specific testing purposes.
        response = self.post('/regions', body={'region': {}})
        self.region2 = response.json_body['region']
        self.region_id2 = self.region2['id']

        service_ref = {'service': {
            'name': uuid.uuid4().hex,
            'enabled': True,
            'type': 'type2'}}
        response = self.post('/services', body=service_ref)
        self.service2 = response.json_body['service']
        self.service_id2 = self.service2['id']

        ref1 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id,
                                             resource_name='volume')
        ref2 = unit.new_registered_limit_ref(service_id=self.service_id2,
                                             resource_name='snapshot')
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        self.registered_limit1 = r.result['registered_limits'][0]
        self.registered_limit2 = r.result['registered_limits'][1]

    def test_create_limit(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume')
        r = self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)
        limits = r.result['limits']

        self. assertIsNotNone(limits[0]['id'])
        self. assertIsNotNone(limits[0]['project_id'])
        for key in ['service_id', 'region_id', 'resource_name',
                    'resource_limit']:
            self.assertEqual(limits[0][key], ref[key])

    def test_create_limit_without_region(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id2,
                                 resource_name='snapshot')
        r = self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)
        limits = r.result['limits']

        self. assertIsNotNone(limits[0]['id'])
        self. assertIsNotNone(limits[0]['project_id'])
        for key in ['service_id', 'resource_name', 'resource_limit']:
            self.assertEqual(limits[0][key], ref[key])
        self.assertIsNone(limits[0].get('region_id'))

    def test_create_multi_limit(self):
        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='volume')
        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot')
        r = self.post(
            '/limits',
            body={'limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        limits = r.result['limits']
        for key in ['service_id', 'resource_name', 'resource_limit']:
            self.assertEqual(limits[0][key], ref1[key])
            self.assertEqual(limits[1][key], ref2[key])
        self.assertEqual(limits[0]['region_id'], ref1['region_id'])
        self.assertIsNone(limits[1].get('region_id'))

    def test_create_limit_with_invalid_input(self):
        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  resource_limit='not_int')
        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  resource_name=123)
        ref3 = unit.new_limit_ref(project_id=self.project_id,
                                  region_id='fake_region')
        for input_limit in [ref1, ref2, ref3]:
            self.post(
                '/limits',
                body={'limits': [input_limit]},
                expected_status=http_client.BAD_REQUEST)

    def test_create_limit_duplicate(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume')
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CONFLICT)

    @test_utils.wip("Skipped until Bug 1744195 is resolved")
    def test_create_limit_without_reference_registered_limit(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id2,
                                 resource_name='volume')
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.FORBIDDEN)

    def test_update_limit(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=10)
        r = self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)
        update_ref = {
            'id': r.result['limits'][0]['id'],
            'resource_limit': 5
        }
        r = self.put(
            '/limits',
            body={'limits': [update_ref]},
            expected_status=http_client.OK)
        new_limits = r.result['limits'][0]

        self.assertEqual(new_limits['resource_limit'], 5)

    def test_update_multi_limit(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=10)
        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot',
                                  resource_limit=10)
        r = self.post(
            '/limits',
            body={'limits': [ref, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['limits'][0]['id']
        update_ref = {
            'id': id1,
            'resource_limit': 5
        }
        update_ref2 = {
            'id': r.result['limits'][1]['id'],
            'resource_limit': 6
        }
        r = self.put(
            '/limits',
            body={'limits': [update_ref, update_ref2]},
            expected_status=http_client.OK)
        new_limits = r.result['limits']
        for limit in new_limits:
            if limit['id'] == id1:
                self.assertEqual(limit['resource_limit'],
                                 update_ref['resource_limit'])
            else:
                self.assertEqual(limit['resource_limit'],
                                 update_ref2['resource_limit'])

    def test_update_limit_not_found(self):
        update_ref = {
            'id': uuid.uuid4().hex,
            'resource_limit': 5
        }
        self.put(
            '/limits',
            body={'limits': [update_ref]},
            expected_status=http_client.NOT_FOUND)

    def test_update_limit_with_invalid_input(self):
        update_ref1 = {
            'id': 'fake_id',
            'resource_limit': 5
        }
        update_ref2 = {
            'id': uuid.uuid4().hex,
            'resource_limit': 'not_int'
        }
        for input_limit in [update_ref1, update_ref2]:
            self.put(
                '/limits',
                body={'limits': [input_limit]},
                expected_status=http_client.BAD_REQUEST)

    def test_list_limit(self):
        r = self.get(
            '/limits',
            expected_status=http_client.OK)
        self.assertEqual([], r.result.get('limits'))

        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='volume')
        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot')
        r = self.post(
            '/limits',
            body={'limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['limits'][0]['id']
        r = self.get(
            '/limits',
            expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(len(limits), 2)
        if limits[0]['id'] == id1:
            self.assertEqual(limits[0]['region_id'], ref1['region_id'])
            self.assertIsNone(limits[1].get('region_id'))
            for key in ['service_id', 'resource_name', 'resource_limit']:
                self.assertEqual(limits[0][key], ref1[key])
                self.assertEqual(limits[1][key], ref2[key])
        else:
            self.assertEqual(limits[1]['region_id'], ref1['region_id'])
            self.assertIsNone(limits[0].get('region_id'))
            for key in ['service_id', 'resource_name', 'resource_limit']:
                self.assertEqual(limits[1][key], ref1[key])
                self.assertEqual(limits[0][key], ref2[key])

        r = self.get(
            '/limits?service_id=%s' % self.service_id2,
            expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(len(limits), 1)
        for key in ['service_id', 'resource_name', 'resource_limit']:
            self.assertEqual(limits[0][key], ref2[key])

        r = self.get(
            '/limits?region_id=%s' % self.region_id,
            expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(len(limits), 1)
        for key in ['service_id', 'region_id', 'resource_name',
                    'resource_limit']:
            self.assertEqual(limits[0][key], ref1[key])

        r = self.get(
            '/limits?resource_name=volume',
            expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(len(limits), 1)
        for key in ['service_id', 'region_id', 'resource_name',
                    'resource_limit']:
            self.assertEqual(limits[0][key], ref1[key])

    def test_show_limit(self):
        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='volume')
        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot')
        r = self.post(
            '/limits',
            body={'limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['limits'][0]['id']
        self.get('/limits/fake_id',
                 expected_status=http_client.NOT_FOUND)
        r = self.get('/limits/%s' % id1,
                     expected_status=http_client.OK)
        limit = r.result['limit']
        for key in ['service_id', 'region_id', 'resource_name',
                    'resource_limit']:
            self.assertEqual(limit[key], ref1[key])

    def test_delete_limit(self):
        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='volume')
        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot')
        r = self.post(
            '/limits',
            body={'limits': [ref1, ref2]},
            expected_status=http_client.CREATED)
        id1 = r.result['limits'][0]['id']
        self.delete('/limits/%s' % id1,
                    expected_status=http_client.NO_CONTENT)
        self.delete('/limits/fake_id',
                    expected_status=http_client.NOT_FOUND)
        r = self.get(
            '/limits',
            expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(len(limits), 1)

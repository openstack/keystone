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
from keystone.common.validation import validators
import keystone.conf
from keystone.tests import unit
from keystone.tests.unit import test_v3

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


class LimitModelTestCase(test_v3.RestfulTestCase):

    def test_get_default_limit_model_response_schema(self):
        schema = {
            'type': 'object',
            'properties': {
                'model': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'description': {'type': 'string'}
                    },
                    'required': ['name', 'description'],
                    'additionalProperties': False,
                },
            },
            'required': ['model'],
            'additionalProperties': False,
        }
        validator = validators.SchemaValidator(schema)
        response = self.get('/limits/model')
        validator.validate(response.json_body)

    def test_head_limit_model(self):
        self.head('/limits/model', expected_status=http_client.OK)

    def test_get_limit_model_returns_default_model(self):
        response = self.get('/limits/model')
        model = response.result
        expected = {
            'model': {
                'name': 'flat',
                'description': (
                    'Limit enforcement and validation does not take project '
                    'hierarchy into consideration.'
                )
            }
        }
        self.assertDictEqual(expected, model)

    def test_get_limit_model_without_token_fails(self):
        self.get(
            '/limits/model', noauth=True,
            expected_status=http_client.UNAUTHORIZED
        )

    def test_head_limit_model_without_token_fails(self):
        self.head(
            '/limits/model', noauth=True,
            expected_status=http_client.UNAUTHORIZED
        )


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
                    'default_limit', 'description']:
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

    def test_create_registered_without_description(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id)
        ref.pop('description')
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        registered_limits = r.result['registered_limits']
        for key in ['service_id', 'region_id', 'resource_name',
                    'default_limit']:
            self.assertEqual(registered_limits[0][key], ref[key])
        self.assertIsNone(registered_limits[0]['description'])

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

    def test_create_registered_limit_return_count(self):
        ref1 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref1]},
            expected_status=http_client.CREATED)
        registered_limits = r.result['registered_limits']
        self.assertEqual(1, len(registered_limits))

        ref2 = unit.new_registered_limit_ref(service_id=self.service_id2,
                                             region_id=self.region_id2)
        ref3 = unit.new_registered_limit_ref(service_id=self.service_id2)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref2, ref3]},
            expected_status=http_client.CREATED)
        registered_limits = r.result['registered_limits']
        self.assertEqual(2, len(registered_limits))

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
            'service_id': self.service_id2,
            'region_id': self.region_id2,
            'resource_name': 'snapshot',
            'default_limit': 5,
            'description': 'test description'
        }
        r = self.patch(
            '/registered_limits/%s' % r.result['registered_limits'][0]['id'],
            body={'registered_limit': update_ref},
            expected_status=http_client.OK)
        new_registered_limits = r.result['registered_limit']

        self.assertEqual(new_registered_limits['service_id'], self.service_id2)
        self.assertEqual(new_registered_limits['region_id'], self.region_id2)
        self.assertEqual(new_registered_limits['resource_name'], 'snapshot')
        self.assertEqual(new_registered_limits['default_limit'], 5)
        self.assertEqual(new_registered_limits['description'],
                         'test description')

    def test_update_registered_limit_description(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id,
                                            resource_name='volume',
                                            default_limit=10)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        update_ref = {
            'description': 'test description'
        }
        registered_limit_id = r.result['registered_limits'][0]['id']
        r = self.patch(
            '/registered_limits/%s' % registered_limit_id,
            body={'registered_limit': update_ref},
            expected_status=http_client.OK)
        new_registered_limits = r.result['registered_limit']
        self.assertEqual(new_registered_limits['description'],
                         'test description')

        update_ref['description'] = ''
        r = self.patch(
            '/registered_limits/%s' % registered_limit_id,
            body={'registered_limit': update_ref},
            expected_status=http_client.OK)
        new_registered_limits = r.result['registered_limit']
        self.assertEqual(new_registered_limits['description'], '')

    def test_update_registered_limit_not_found(self):
        update_ref = {
            'service_id': self.service_id,
            'region_id': self.region_id,
            'resource_name': 'snapshot',
            'default_limit': 5
        }
        self.patch(
            '/registered_limits/%s' % uuid.uuid4().hex,
            body={'registered_limit': update_ref},
            expected_status=http_client.NOT_FOUND)

    def test_update_registered_limit_with_invalid_input(self):
        ref = unit.new_registered_limit_ref(service_id=self.service_id,
                                            region_id=self.region_id,
                                            resource_name='volume',
                                            default_limit=10)
        r = self.post(
            '/registered_limits',
            body={'registered_limits': [ref]},
            expected_status=http_client.CREATED)
        reg_id = r.result['registered_limits'][0]['id']

        update_ref1 = unit.new_registered_limit_ref(service_id='fake_id')
        update_ref2 = unit.new_registered_limit_ref(default_limit='not_int')
        update_ref3 = unit.new_registered_limit_ref(resource_name=123)
        update_ref4 = unit.new_registered_limit_ref(region_id='fake_region')
        update_ref5 = unit.new_registered_limit_ref(description=123)
        for input_limit in [update_ref1, update_ref2, update_ref3,
                            update_ref4, update_ref5]:
            self.patch(
                '/registered_limits/%s' % reg_id,
                body={'registered_limit': input_limit},
                expected_status=http_client.BAD_REQUEST)

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
            'service_id': self.service_id2,
            'region_id': self.region_id2,
            'resource_name': 'snapshot',
            'default_limit': 5
        }
        self.patch(
            '/registered_limits/%s' % r.result['registered_limits'][0]['id'],
            body={'registered_limit': update_ref},
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
                    'default_limit', 'description']:
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
        ref3 = unit.new_registered_limit_ref(service_id=self.service_id,
                                             region_id=self.region_id,
                                             resource_name='backup')
        self.post(
            '/registered_limits',
            body={'registered_limits': [ref1, ref2, ref3]},
            expected_status=http_client.CREATED)

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

        self.assertIsNotNone(limits[0]['id'])
        self.assertIsNotNone(limits[0]['project_id'])
        for key in ['service_id', 'region_id', 'resource_name',
                    'resource_limit', 'description']:
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

        self.assertIsNotNone(limits[0]['id'])
        self.assertIsNotNone(limits[0]['project_id'])
        for key in ['service_id', 'resource_name', 'resource_limit']:
            self.assertEqual(limits[0][key], ref[key])
        self.assertIsNone(limits[0].get('region_id'))

    def test_create_limit_without_description(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume')
        ref.pop('description')
        r = self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)
        limits = r.result['limits']

        self.assertIsNotNone(limits[0]['id'])
        self.assertIsNotNone(limits[0]['project_id'])
        for key in ['service_id', 'region_id', 'resource_name',
                    'resource_limit']:
            self.assertEqual(limits[0][key], ref[key])
        self.assertIsNone(limits[0]['description'])

    def test_create_limit_with_domain_as_project(self):
        ref = unit.new_limit_ref(project_id=self.domain_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume')
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.BAD_REQUEST)

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

    def test_create_limit_return_count(self):
        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='volume')
        r = self.post(
            '/limits',
            body={'limits': [ref1]},
            expected_status=http_client.CREATED)
        limits = r.result['limits']
        self.assertEqual(1, len(limits))

        ref2 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot')
        ref3 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='backup')
        r = self.post(
            '/limits',
            body={'limits': [ref2, ref3]},
            expected_status=http_client.CREATED)
        limits = r.result['limits']
        self.assertEqual(2, len(limits))

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
            'resource_limit': 5,
            'description': 'test description'
        }
        r = self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_ref},
            expected_status=http_client.OK)
        new_limits = r.result['limit']

        self.assertEqual(new_limits['resource_limit'], 5)
        self.assertEqual(new_limits['description'], 'test description')

    def test_update_limit_not_found(self):
        update_ref = {
            'resource_limit': 5
        }
        self.patch(
            '/limits/%s' % uuid.uuid4().hex,
            body={'limit': update_ref},
            expected_status=http_client.NOT_FOUND)

    def test_update_limit_with_invalid_input(self):
        ref = unit.new_limit_ref(project_id=self.project_id,
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=10)
        r = self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)
        limit_id = r.result['limits'][0]['id']

        invalid_resource_limit_update = {
            'resource_limit': 'not_int'
        }
        invalid_description_update = {
            'description': 123
        }
        for input_limit in [invalid_resource_limit_update,
                            invalid_description_update]:
            self.patch(
                '/limits/%s' % limit_id,
                body={'limit': input_limit},
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

    def test_list_limit_with_project_id_filter(self):
        # Create a new projects and a 'non-admin' role for test. The assignment
        # is like:
        #
        # self.user -- admin -- self.project (default)
        # self.user -- non-admin -- the new project
        # self.user -- admin -- system
        project_2 = unit.new_project_ref(domain_id=self.domain_id)
        project_2_id = project_2['id']
        PROVIDERS.resource_api.create_project(project_2_id, project_2)

        role_2 = unit.new_role_ref(name='non-admin')
        role_2_id = role_2['id']
        PROVIDERS.role_api.create_role(role_2_id, role_2)

        PROVIDERS.assignment_api.add_role_to_user_and_project(
            self.user_id, project_2_id, role_2_id)
        PROVIDERS.assignment_api.create_system_grant_for_user(
            self.user_id, self.role['id'])

        # create two limit in different projects for test.
        ref1 = unit.new_limit_ref(project_id=self.project_id,
                                  service_id=self.service_id,
                                  region_id=self.region_id,
                                  resource_name='volume')
        ref2 = unit.new_limit_ref(project_id=project_2_id,
                                  service_id=self.service_id2,
                                  resource_name='snapshot')
        self.post(
            '/limits',
            body={'limits': [ref1, ref2]},
            expected_status=http_client.CREATED)

        # non system scoped request will get the limits in its project.
        r = self.get('/limits', expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(1, len(limits))
        self.assertEqual(self.project_id, limits[0]['project_id'])

        r = self.get(
            '/limits', expected_status=http_client.OK,
            auth=self.build_authentication_request(
                user_id=self.user['id'], password=self.user['password'],
                project_id=project_2_id))
        limits = r.result['limits']
        self.assertEqual(1, len(limits))
        self.assertEqual(project_2_id, limits[0]['project_id'])

        # if non system scoped request contain project_id filter, keystone
        # will return an empty list.
        r = self.get(
            '/limits?project_id=%s' % self.project_id,
            expected_status=http_client.OK)
        limits = r.result['limits']
        self.assertEqual(0, len(limits))

        # a system scoped request can specify the project_id filter
        r = self.get(
            '/limits?project_id=%s' % self.project_id,
            expected_status=http_client.OK,
            auth=self.build_authentication_request(
                user_id=self.user['id'], password=self.user['password'],
                system=True)
        )
        limits = r.result['limits']
        self.assertEqual(1, len(limits))
        self.assertEqual(self.project_id, limits[0]['project_id'])

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
                    'resource_limit', 'description']:
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


class StrictTwoLevelLimitsTestCase(LimitsTestCase):

    def setUp(self):
        super(StrictTwoLevelLimitsTestCase, self).setUp()
        # create two hierarchical projects trees for test.
        #   A        D
        #  / \      / \
        # B   C    E   F
        project_ref = {'project': {'name': 'A', 'enabled': True}}
        response = self.post('/projects', body=project_ref)
        self.project_A = response.json_body['project']
        project_ref = {'project': {'name': 'B', 'enabled': True,
                                   'parent_id': self.project_A['id']}}
        response = self.post('/projects', body=project_ref)
        self.project_B = response.json_body['project']
        project_ref = {'project': {'name': 'C', 'enabled': True,
                                   'parent_id': self.project_A['id']}}
        response = self.post('/projects', body=project_ref)
        self.project_C = response.json_body['project']

        project_ref = {'project': {'name': 'D', 'enabled': True}}
        response = self.post('/projects', body=project_ref)
        self.project_D = response.json_body['project']
        project_ref = {'project': {'name': 'E', 'enabled': True,
                                   'parent_id': self.project_D['id']}}
        response = self.post('/projects', body=project_ref)
        self.project_E = response.json_body['project']
        project_ref = {'project': {'name': 'F', 'enabled': True,
                                   'parent_id': self.project_D['id']}}
        response = self.post('/projects', body=project_ref)
        self.project_F = response.json_body['project']

    def config_overrides(self):
        super(StrictTwoLevelLimitsTestCase, self).config_overrides()
        self.config_fixture.config(group='unified_limit',
                                   enforcement_model='strict_two_level')

    def test_create_child_limit(self):
        # when A is 20, success to create B to 15, C to 18.
        #     A,20             A,20
        #    / \      -->     / \
        #   B   C           B,15 C,18
        ref = unit.new_limit_ref(project_id=self.project_A['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=20)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_B['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=15)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_C['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=18)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

    def test_create_child_limit_break_hierarchical_tree(self):
        # when A is 20, success to create B to 15, but fail to create C to 21.
        #     A,20             A,20
        #    / \      -->     / \
        #   B   C           B,15 C
        #
        #     A,20              A,20
        #    / \      -/->      / \
        #  B,15 C            B,15 C,21
        ref = unit.new_limit_ref(project_id=self.project_A['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=20)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_B['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=15)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_C['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=21)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.FORBIDDEN)

    def test_create_child_with_default_parent(self):
        # If A is not set, the default value is 10 (from registered limit).
        # success to create B to 5, but fail to create C to 11.
        #     A(10)             A(10)
        #    / \      -->      / \
        #   B   C            B,5  C
        #
        #     A(10)             A(10)
        #    / \     -/->      / \
        #   B,5   C          B,5  C,11
        ref = unit.new_limit_ref(project_id=self.project_B['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=5)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_C['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=11)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.FORBIDDEN)

    def test_create_parent_limit(self):
        # When B is 9 , success to set A to 12
        #     A              A,12
        #    / \    -->      / \
        #  B,9  C          B,9  C
        ref = unit.new_limit_ref(project_id=self.project_B['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=9)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_A['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=12)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

    def test_create_parent_limit_break_hierarchical_tree(self):
        # When B is 9 , fail to set A to 8
        #     A              A,8
        #    / \    -/->     / \
        #  B,9  C          B,9  C
        ref = unit.new_limit_ref(project_id=self.project_B['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=9)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.CREATED)

        ref = unit.new_limit_ref(project_id=self.project_A['id'],
                                 service_id=self.service_id,
                                 region_id=self.region_id,
                                 resource_name='volume',
                                 resource_limit=8)
        self.post(
            '/limits',
            body={'limits': [ref]},
            expected_status=http_client.FORBIDDEN)

    def test_create_multi_limits(self):
        # success to create a tree in one request like:
        #    A,12         D,9
        #    / \          / \
        #  B,9  C,5    E,5   F,4
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=12)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=9)
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=5)
        ref_D = unit.new_limit_ref(project_id=self.project_D['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=9)
        ref_E = unit.new_limit_ref(project_id=self.project_E['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=5)
        ref_F = unit.new_limit_ref(project_id=self.project_F['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=4)
        self.post(
            '/limits',
            body={'limits': [ref_A, ref_B, ref_C, ref_D, ref_E, ref_F]},
            expected_status=http_client.CREATED)

    def test_create_multi_limits_invalid_input(self):
        # fail to create a tree in one request like:
        #    A,12         D,9
        #    / \          / \
        #  B,9  C,5    E,5   F,10
        # because F will break the second limit tree.
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=12)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=9)
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=5)
        ref_D = unit.new_limit_ref(project_id=self.project_D['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=9)
        ref_E = unit.new_limit_ref(project_id=self.project_E['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=5)
        ref_F = unit.new_limit_ref(project_id=self.project_F['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=10)
        self.post(
            '/limits',
            body={'limits': [ref_A, ref_B, ref_C, ref_D, ref_E, ref_F]},
            expected_status=http_client.FORBIDDEN)

    def test_create_multi_limits_break_hierarchical_tree(self):
        # when there is some hierarchical_trees already like:
        #    A,12          D
        #    / \          / \
        #  B,9  C       E,5   F
        # fail to set C to 5 and D to 4 in one request like:
        #    A,12         D,4
        #    / \          / \
        #  B,9  C,5    E,5   F
        # because D will break the second limit tree.
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=12)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=9)
        ref_E = unit.new_limit_ref(project_id=self.project_E['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=5)
        self.post(
            '/limits',
            body={'limits': [ref_A, ref_B, ref_E]},
            expected_status=http_client.CREATED)

        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=5)
        ref_D = unit.new_limit_ref(project_id=self.project_D['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=4)
        self.post(
            '/limits',
            body={'limits': [ref_C, ref_D]},
            expected_status=http_client.FORBIDDEN)

    def test_update_child_limit(self):
        # Success to update C to 9
        #     A,10             A,10
        #    / \      -->     / \
        #  B,6  C,7         B,6  C,9
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=10)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=6)
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=7)
        self.post(
            '/limits',
            body={'limits': [ref_A, ref_B]},
            expected_status=http_client.CREATED)
        r = self.post(
            '/limits',
            body={'limits': [ref_C]},
            expected_status=http_client.CREATED)

        update_dict = {'resource_limit': 9}
        self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_dict},
            expected_status=http_client.OK)

    def test_update_child_limit_break_hierarchical_tree(self):
        # Fail to update C to 11
        #     A,10             A,10
        #    / \      -/->     / \
        #  B,6  C,7         B,6  C,11
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=10)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=6)
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=7)
        self.post(
            '/limits',
            body={'limits': [ref_A, ref_B]},
            expected_status=http_client.CREATED)
        r = self.post(
            '/limits',
            body={'limits': [ref_C]},
            expected_status=http_client.CREATED)

        update_dict = {'resource_limit': 11}
        self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_dict},
            expected_status=http_client.FORBIDDEN)

    def test_update_child_limit_with_default_parent(self):
        # If A is not set, the default value is 10 (from registered limit).
        # Success to update C to 9 but fail to update C to 11
        #     A,(10)           A,(10)
        #    / \      -->     / \
        #   B,  C,7          B  C,9
        #
        #     A,(10)            A,(10)
        #    / \      -/->     / \
        #   B,  C,7           B  C,11
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=7)
        r = self.post(
            '/limits',
            body={'limits': [ref_C]},
            expected_status=http_client.CREATED)

        update_dict = {'resource_limit': 9}
        self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_dict},
            expected_status=http_client.OK)

        update_dict = {'resource_limit': 11}
        self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_dict},
            expected_status=http_client.FORBIDDEN)

    def test_update_parent_limit(self):
        # Success to update A to 8
        #     A,10             A,8
        #    / \      -->     / \
        #  B,6  C,7         B,6  C,7
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=10)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=6)
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=7)
        r = self.post(
            '/limits',
            body={'limits': [ref_A]},
            expected_status=http_client.CREATED)
        self.post(
            '/limits',
            body={'limits': [ref_B, ref_C]},
            expected_status=http_client.CREATED)

        update_dict = {'resource_limit': 8}
        self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_dict},
            expected_status=http_client.OK)

    def test_update_parent_limit_break_hierarchical_tree(self):
        # Fail to update A to 6
        #     A,10             A,6
        #    / \      -/->     / \
        #  B,6  C,7         B,6  C,7
        ref_A = unit.new_limit_ref(project_id=self.project_A['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=10)
        ref_B = unit.new_limit_ref(project_id=self.project_B['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=6)
        ref_C = unit.new_limit_ref(project_id=self.project_C['id'],
                                   service_id=self.service_id,
                                   region_id=self.region_id,
                                   resource_name='volume',
                                   resource_limit=7)
        r = self.post(
            '/limits',
            body={'limits': [ref_A]},
            expected_status=http_client.CREATED)
        self.post(
            '/limits',
            body={'limits': [ref_B, ref_C]},
            expected_status=http_client.CREATED)

        update_dict = {'resource_limit': 6}
        self.patch(
            '/limits/%s' % r.result['limits'][0]['id'],
            body={'limit': update_dict},
            expected_status=http_client.FORBIDDEN)

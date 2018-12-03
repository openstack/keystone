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

from keystone.common import driver_hints
from keystone.common import provider_api
from keystone import exception
from keystone.tests import unit

PROVIDERS = provider_api.ProviderAPIs


class RegisteredLimitTests(object):

    def test_create_registered_limit_crud(self):
        # create one, return it.
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex,
            description='test description')
        reg_limits = PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1])
        self.assertDictEqual(registered_limit_1, reg_limits[0])

        # create another two, return them.
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=5, id=uuid.uuid4().hex)
        registered_limit_3 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='backup', default_limit=5, id=uuid.uuid4().hex)
        reg_limits = PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_2, registered_limit_3])
        self.assertEqual(2, len(reg_limits))
        for reg_limit in reg_limits:
            if reg_limit['id'] == registered_limit_2['id']:
                self.assertDictEqual(registered_limit_2, reg_limit)
            if reg_limit['id'] == registered_limit_3['id']:
                self.assertDictEqual(registered_limit_3, reg_limit)

    def test_create_registered_limit_duplicate(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1])

        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.Conflict,
                          PROVIDERS.unified_limit_api.create_registered_limits,
                          [registered_limit_2])

    def test_create_multi_registered_limits_duplicate(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1])

        # Create with a duplicated one and a normal one. Both of them will not
        # be created.
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_3 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.Conflict,
                          PROVIDERS.unified_limit_api.create_registered_limits,
                          [registered_limit_2, registered_limit_3])

        reg_limits = PROVIDERS.unified_limit_api.list_registered_limits()
        self.assertEqual(1, len(reg_limits))
        self.assertEqual(registered_limit_1['id'], reg_limits[0]['id'])

    def test_create_registered_limit_invalid_service(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=uuid.uuid4().hex,
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.unified_limit_api.create_registered_limits,
                          [registered_limit_1])

    def test_create_registered_limit_invalid_region(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=uuid.uuid4().hex,
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.unified_limit_api.create_registered_limits,
                          [registered_limit_1])

    def test_create_registered_limit_description_none(self):
        registered_limit = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex,
            description=None)
        res = PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit])
        self.assertIsNone(res[0]['description'])

    def test_create_registered_limit_without_description(self):
        registered_limit = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit.pop('description')
        res = PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit])
        self.assertIsNone(res[0]['description'])

    def test_update_registered_limit(self):
        # create two registered limits
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        expect_region = 'region_two'
        registered_limit_update = {'id': registered_limit_1['id'],
                                   'region_id': expect_region}
        res = PROVIDERS.unified_limit_api.update_registered_limit(
            registered_limit_1['id'], registered_limit_update)
        self.assertEqual(expect_region, res['region_id'])

        # 'id' can be omitted in the update body
        registered_limit_update = {'region_id': expect_region}
        res = PROVIDERS.unified_limit_api.update_registered_limit(
            registered_limit_2['id'], registered_limit_update)
        self.assertEqual(expect_region, res['region_id'])

    def test_update_registered_limit_invalid_input_return_bad_request(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1])

        update_ref = {'id': registered_limit_1['id'],
                      'service_id': uuid.uuid4().hex}
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.unified_limit_api.update_registered_limit,
                          registered_limit_1['id'], update_ref)

        update_ref = {'id': registered_limit_1['id'],
                      'region_id': 'fake_id'}
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.unified_limit_api.update_registered_limit,
                          registered_limit_1['id'], update_ref)

    def test_update_registered_limit_duplicate(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        # Update registered_limit1 to registered_limit2
        update_ref = {'id': registered_limit_1['id'],
                      'region_id': self.region_two['id'],
                      'resource_name': 'snapshot'}
        self.assertRaises(exception.Conflict,
                          PROVIDERS.unified_limit_api.update_registered_limit,
                          registered_limit_1['id'], update_ref)

    def test_update_registered_limit_when_reference_limit_exist(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1])
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1])

        registered_limit_update = {'id': registered_limit_1['id'],
                                   'region_id': 'region_two'}

        self.assertRaises(exception.RegisteredLimitError,
                          PROVIDERS.unified_limit_api.update_registered_limit,
                          registered_limit_1['id'], registered_limit_update)

        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_2])
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_2])

        registered_limit_update = {'id': registered_limit_2['id'],
                                   'region_id': 'region_two'}

        self.assertRaises(exception.RegisteredLimitError,
                          PROVIDERS.unified_limit_api.update_registered_limit,
                          registered_limit_2['id'], registered_limit_update)

    def test_list_registered_limits(self):
        # create two registered limits
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=5, id=uuid.uuid4().hex)
        reg_limits_1 = PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        # list
        reg_limits_2 = PROVIDERS.unified_limit_api.list_registered_limits()
        self.assertEqual(2, len(reg_limits_2))
        self.assertDictEqual(reg_limits_1[0], reg_limits_2[0])
        self.assertDictEqual(reg_limits_1[1], reg_limits_2[1])

    def test_list_registered_limit_by_limit(self):
        self.config_fixture.config(list_limit=1)
        # create two registered limits
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        # list, limit is 1
        hints = driver_hints.Hints()
        reg_limits = PROVIDERS.unified_limit_api.list_registered_limits(
            hints=hints)
        self.assertEqual(1, len(reg_limits))

        if reg_limits[0]['id'] == registered_limit_1['id']:
            self.assertDictEqual(registered_limit_1, reg_limits[0])
        else:
            self.assertDictEqual(registered_limit_2, reg_limits[0])

    def test_list_registered_limit_by_filter(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        hints = driver_hints.Hints()
        hints.add_filter('service_id', self.service_one['id'])
        res = PROVIDERS.unified_limit_api.list_registered_limits(hints)
        self.assertEqual(2, len(res))

        hints = driver_hints.Hints()
        hints.add_filter('region_id', self.region_one['id'])
        res = PROVIDERS.unified_limit_api.list_registered_limits(hints)
        self.assertEqual(1, len(res))

        hints = driver_hints.Hints()
        hints.add_filter('resource_name', 'backup')
        res = PROVIDERS.unified_limit_api.list_registered_limits(hints)
        self.assertEqual(0, len(res))

    def test_get_registered_limit(self):
        # create two registered limits
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        # show one
        res = PROVIDERS.unified_limit_api.get_registered_limit(
            registered_limit_2['id'])
        self.assertDictEqual(registered_limit_2, res)

    def test_get_registered_limit_returns_not_found(self):
        self.assertRaises(exception.RegisteredLimitNotFound,
                          PROVIDERS.unified_limit_api.get_registered_limit,
                          uuid.uuid4().hex)

    def test_delete_registered_limit(self):
        # create two registered limits
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='snapshot', default_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1, registered_limit_2])

        # delete one
        PROVIDERS.unified_limit_api.delete_registered_limit(
            registered_limit_1['id'])
        self.assertRaises(exception.RegisteredLimitNotFound,
                          PROVIDERS.unified_limit_api.get_registered_limit,
                          registered_limit_1['id'])
        reg_limits = PROVIDERS.unified_limit_api.list_registered_limits()
        self.assertEqual(1, len(reg_limits))
        self.assertEqual(registered_limit_2['id'], reg_limits[0]['id'])

    def test_delete_registered_limit_returns_not_found(self):
        self.assertRaises(exception.RegisteredLimitNotFound,
                          PROVIDERS.unified_limit_api.delete_registered_limit,
                          uuid.uuid4().hex)

    def test_delete_registered_limit_when_reference_limit_exist(self):
        registered_limit_1 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_1])
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1])

        self.assertRaises(exception.RegisteredLimitError,
                          PROVIDERS.unified_limit_api.delete_registered_limit,
                          registered_limit_1['id'])

        registered_limit_2 = unit.new_registered_limit_ref(
            service_id=self.service_one['id'],
            resource_name='volume', default_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_registered_limits(
            [registered_limit_2])
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_2])

        self.assertRaises(exception.RegisteredLimitError,
                          PROVIDERS.unified_limit_api.delete_registered_limit,
                          registered_limit_2['id'])


class LimitTests(object):

    def test_default_enforcement_model_is_flat(self):
        expected = {
            'description': ('Limit enforcement and validation does not take '
                            'project hierarchy into consideration.'),
            'name': 'flat'
        }
        self.assertEqual(expected, PROVIDERS.unified_limit_api.get_model())

    def test_registering_unsupported_enforcement_model_fails(self):
        self.assertRaises(
            ValueError, self.config_fixture.config, group='unified_limit',
            enforcement_model=uuid.uuid4().hex
        )

    def test_create_project_limit(self):
        # create one, return it.
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            description='test description',
            domain_id=None)
        limits = PROVIDERS.unified_limit_api.create_limits([limit_1])
        self.assertDictEqual(limit_1, limits[0])

        # create another two, return them.
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex,
            domain_id=None)
        limit_3 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='backup', resource_limit=5, id=uuid.uuid4().hex,
            domain_id=None)

        limits = PROVIDERS.unified_limit_api.create_limits([limit_2, limit_3])
        for limit in limits:
            if limit['id'] == limit_2['id']:
                self.assertDictEqual(limit_2, limit)
            if limit['id'] == limit_3['id']:
                self.assertDictEqual(limit_3, limit)

    def test_create_domain_limit(self):
        limit_1 = unit.new_limit_ref(
            project_id=None,
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            description='test description',
            domain_id=self.domain_default['id'])
        limits = PROVIDERS.unified_limit_api.create_limits([limit_1])
        self.assertDictEqual(limit_1, limits[0])

    def test_create_project_limit_duplicate(self):
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1])

        # use different id but the same project_id, service_id and region_id
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.Conflict,
                          PROVIDERS.unified_limit_api.create_limits,
                          [limit_1])

    def test_create_domain_limit_duplicate(self):
        limit_1 = unit.new_limit_ref(
            project_id=None,
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=self.domain_default['id'])
        PROVIDERS.unified_limit_api.create_limits([limit_1])

        # use different id but the same domain_id, service_id and region_id
        limit_1 = unit.new_limit_ref(
            project_id=None,
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=self.domain_default['id'])
        self.assertRaises(exception.Conflict,
                          PROVIDERS.unified_limit_api.create_limits,
                          [limit_1])

    def test_create_limit_with_invalid_service_raises_validation_error(self):
        limit = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=uuid.uuid4().hex,
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.unified_limit_api.create_limits,
                          [limit])

    def test_create_limit_with_invalid_region_raises_validation_error(self):
        limit = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=uuid.uuid4().hex,
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.unified_limit_api.create_limits,
                          [limit])

    def test_create_limit_without_reference_registered_limit(self):
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        self.assertRaises(exception.NoLimitReference,
                          PROVIDERS.unified_limit_api.create_limits,
                          [limit_1])

    def test_create_limit_description_none(self):
        limit = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            description=None)
        res = PROVIDERS.unified_limit_api.create_limits([limit])
        self.assertIsNone(res[0]['description'])

    def test_create_limit_without_description(self):
        limit = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        limit.pop('description')
        res = PROVIDERS.unified_limit_api.create_limits([limit])
        self.assertIsNone(res[0]['description'])

    def test_update_limit(self):
        # create two limits
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])

        expect_limit = 8
        limit_update = {'id': limit_1['id'],
                        'resource_limit': expect_limit}
        res = PROVIDERS.unified_limit_api.update_limit(limit_1['id'],
                                                       limit_update)
        self.assertEqual(expect_limit, res['resource_limit'])

        # 'id' can be omitted in the update body
        limit_update = {'resource_limit': expect_limit}
        res = PROVIDERS.unified_limit_api.update_limit(limit_2['id'],
                                                       limit_update)
        self.assertEqual(expect_limit, res['resource_limit'])

    def test_list_limits(self):
        # create two limits
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=None)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex,
            domain_id=None)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])

        # list
        hints = driver_hints.Hints()
        hints.add_filter('project_id', self.project_bar['id'])
        limits = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(2, len(limits))
        for re in limits:
            if re['id'] == limit_1['id']:
                self.assertDictEqual(limit_1, re)
            if re['id'] == limit_2['id']:
                self.assertDictEqual(limit_2, re)

    def test_list_limit_by_limit(self):
        self.config_fixture.config(list_limit=1)
        # create two limits
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=None)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex,
            domain_id=None)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])

        # list, limit is 1
        hints = driver_hints.Hints()
        limits = PROVIDERS.unified_limit_api.list_limits(hints=hints)
        self.assertEqual(1, len(limits))
        if limits[0]['id'] == limit_1['id']:
            self.assertDictEqual(limit_1, limits[0])
        else:
            self.assertDictEqual(limit_2, limits[0])

    def test_list_limit_by_filter(self):
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=None)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_baz['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=None)
        limit_3 = unit.new_limit_ref(
            project_id=None,
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=self.domain_default['id'])
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2, limit_3])

        hints = driver_hints.Hints()
        hints.add_filter('service_id', self.service_one['id'])
        res = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(3, len(res))

        hints = driver_hints.Hints()
        hints.add_filter('region_id', self.region_one['id'])
        res = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(1, len(res))
        self.assertDictEqual(limit_1, res[0])

        hints = driver_hints.Hints()
        hints.add_filter('resource_name', 'backup')
        res = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(0, len(res))

        hints = driver_hints.Hints()
        hints.add_filter('project_id', self.project_bar['id'])
        res = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(1, len(res))

        hints = driver_hints.Hints()
        hints.add_filter('domain_id', self.domain_default['id'])
        res = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(1, len(res))

    def test_list_limit_by_multi_filter_with_project_id(self):
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_baz['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=10, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])

        hints = driver_hints.Hints()
        hints.add_filter('service_id', self.service_one['id'])
        hints.add_filter('project_id', self.project_bar['id'])
        res = PROVIDERS.unified_limit_api.list_limits(hints)
        self.assertEqual(1, len(res))

    def test_get_limit(self):
        # create two limits
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex,
            domain_id=None)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex,
            domain_id=None)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])

        # show one
        res = PROVIDERS.unified_limit_api.get_limit(limit_2['id'])
        self.assertDictEqual(limit_2, res)

    def test_get_limit_returns_not_found(self):
        self.assertRaises(exception.LimitNotFound,
                          PROVIDERS.unified_limit_api.get_limit,
                          uuid.uuid4().hex)

    def test_delete_limit(self):
        # create two limits
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])
        # delete one
        PROVIDERS.unified_limit_api.delete_limit(limit_1['id'])
        # delete again
        self.assertRaises(exception.LimitNotFound,
                          PROVIDERS.unified_limit_api.get_limit,
                          limit_1['id'])

    def test_delete_limit_returns_not_found(self):
        self.assertRaises(exception.LimitNotFound,
                          PROVIDERS.unified_limit_api.delete_limit,
                          uuid.uuid4().hex)

    def test_delete_limit_project(self):
        # create two limits
        limit_1 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_one['id'],
            resource_name='volume', resource_limit=10, id=uuid.uuid4().hex)
        limit_2 = unit.new_limit_ref(
            project_id=self.project_bar['id'],
            service_id=self.service_one['id'],
            region_id=self.region_two['id'],
            resource_name='snapshot', resource_limit=5, id=uuid.uuid4().hex)
        PROVIDERS.unified_limit_api.create_limits([limit_1, limit_2])

        # delete a unrelated project, the limits should still be there.
        PROVIDERS.resource_api.delete_project(self.project_baz['id'])
        ref = PROVIDERS.unified_limit_api.list_limits()
        self.assertEqual(2, len(ref))

        # delete the referenced project, the limits should be deleted as well.
        PROVIDERS.resource_api.delete_project(self.project_bar['id'])
        ref = PROVIDERS.unified_limit_api.list_limits()
        self.assertEqual([], ref)

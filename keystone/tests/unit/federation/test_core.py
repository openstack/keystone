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

from keystone.common import provider_api
from keystone import exception
from keystone.tests import unit
from keystone.tests.unit import default_fixtures
from keystone.tests.unit.ksfixtures import database
from keystone.tests.unit import mapping_fixtures

PROVIDERS = provider_api.ProviderAPIs


class TestFederationProtocol(unit.TestCase):

    def setUp(self):
        super(TestFederationProtocol, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)
        self.idp = {
            'id': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        PROVIDERS.federation_api.create_idp(self.idp['id'], self.idp)
        self.mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        self.mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )

    def test_create_protocol(self):
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        self.assertEqual(protocol['id'], protocol_ret['id'])

    def test_create_protocol_with_invalid_mapping_id(self):
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': uuid.uuid4().hex
        }
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.federation_api.create_protocol,
                          self.idp['id'],
                          protocol['id'],
                          protocol)

    def test_create_protocol_with_remote_id_attribute(self):
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id'],
            'remote_id_attribute': uuid.uuid4().hex
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        self.assertEqual(protocol['remote_id_attribute'],
                         protocol_ret['remote_id_attribute'])

    def test_update_protocol(self):
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        self.assertEqual(protocol['id'], protocol_ret['id'])
        new_mapping = mapping_fixtures.MAPPING_EPHEMERAL_USER
        new_mapping['id'] = uuid.uuid4().hex
        PROVIDERS.federation_api.create_mapping(new_mapping['id'], new_mapping)
        protocol['mapping_id'] = new_mapping['id']
        protocol_ret = PROVIDERS.federation_api.update_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        self.assertEqual(protocol['id'], protocol_ret['id'])
        self.assertEqual(new_mapping['id'], protocol_ret['mapping_id'])

    def test_update_protocol_with_invalid_mapping_id(self):
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        self.assertEqual(protocol['id'], protocol_ret['id'])
        protocol['mapping_id'] = uuid.uuid4().hex
        self.assertRaises(exception.ValidationError,
                          PROVIDERS.federation_api.update_protocol,
                          self.idp['id'],
                          protocol['id'],
                          protocol)

    def test_update_protocol_with_remote_id_attribute(self):
        protocol = {
            'id': uuid.uuid4().hex,
            'mapping_id': self.mapping['id']
        }
        protocol_ret = PROVIDERS.federation_api.create_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        new_remote_id_attribute = uuid.uuid4().hex
        protocol['remote_id_attribute'] = new_remote_id_attribute
        protocol_ret = PROVIDERS.federation_api.update_protocol(
            self.idp['id'], protocol['id'], protocol
        )
        self.assertEqual(protocol['remote_id_attribute'],
                         protocol_ret['remote_id_attribute'])

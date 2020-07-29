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
from keystone.tests.unit.identity.shadow_users import test_backend
from keystone.tests.unit.identity.shadow_users import test_core
from keystone.tests.unit.ksfixtures import database

PROVIDERS = provider_api.ProviderAPIs


class ShadowUsersTests(unit.TestCase,
                       test_backend.ShadowUsersBackendTests,
                       test_core.ShadowUsersCoreTests):
    def setUp(self):
        super(ShadowUsersTests, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        PROVIDERS.resource_api.create_domain(
            default_fixtures.ROOT_DOMAIN['id'], default_fixtures.ROOT_DOMAIN)
        self.idp = {
            'id': uuid.uuid4().hex,
            'enabled': True,
            'description': uuid.uuid4().hex
        }
        self.mapping = {
            'id': uuid.uuid4().hex,
        }
        self.protocol = {
            'id': uuid.uuid4().hex,
            'idp_id': self.idp['id'],
            'mapping_id': self.mapping['id']
        }
        self.federated_user = {
            'idp_id': self.idp['id'],
            'protocol_id': self.protocol['id'],
            'unique_id': uuid.uuid4().hex,
            'display_name': uuid.uuid4().hex
        }
        self.email = uuid.uuid4().hex
        PROVIDERS.federation_api.create_idp(self.idp['id'], self.idp)
        PROVIDERS.federation_api.create_mapping(
            self.mapping['id'], self.mapping
        )
        PROVIDERS.federation_api.create_protocol(
            self.idp['id'], self.protocol['id'], self.protocol)
        self.domain_id = (
            PROVIDERS.federation_api.get_idp(self.idp['id'])['domain_id'])


class TestUserWithFederatedUser(ShadowUsersTests):

    def setUp(self):
        super(TestUserWithFederatedUser, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()

    def assertFederatedDictsEqual(self, fed_dict, fed_object):
        self.assertEqual(fed_dict['idp_id'], fed_object['idp_id'])
        self.assertEqual(fed_dict['protocol_id'],
                         fed_object['protocols'][0]['protocol_id'])
        self.assertEqual(fed_dict['unique_id'],
                         fed_object['protocols'][0]['unique_id'])

    def test_get_user_when_user_has_federated_object(self):
        fed_dict = unit.new_federated_user_ref(idp_id=self.idp['id'],
                                               protocol_id=self.protocol['id'])
        user = self.shadow_users_api.create_federated_user(
            self.domain_id, fed_dict)

        # test that the user returns a federated object and that there is only
        # one returned
        user_ref = self.identity_api.get_user(user['id'])
        self.assertIn('federated', user_ref)
        self.assertEqual(1, len(user_ref['federated']))

        self.assertFederatedDictsEqual(fed_dict, user_ref['federated'][0])

    def test_create_user_with_invalid_idp_and_protocol_fails(self):
        baduser = unit.new_user_ref(domain_id=self.domain_id)
        baduser['federated'] = [
            {
                'idp_id': 'fakeidp',
                'protocols': [
                    {
                        'protocol_id': 'nonexistent',
                        'unique_id': 'unknown'
                    }
                ]
            }
        ]
        # Check validation works by throwing a federated object with
        # invalid idp_id, protocol_id inside the user passed to create_user.
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          baduser)

        baduser['federated'][0]['idp_id'] = self.idp['id']
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          baduser)

    def test_create_user_with_federated_attributes(self):
        # Create the schema of a federated attribute being passed in with a
        # user.
        user = unit.new_user_ref(domain_id=self.domain_id)
        unique_id = uuid.uuid4().hex
        user['federated'] = [
            {
                'idp_id': self.idp['id'],
                'protocols': [
                    {
                        'protocol_id': self.protocol['id'],
                        'unique_id': unique_id
                    }
                ]
            }
        ]

        # Test that there are no current federated_users that match our users
        # federated object and create the user
        self.assertRaises(exception.UserNotFound,
                          self.shadow_users_api.get_federated_user,
                          self.idp['id'],
                          self.protocol['id'],
                          unique_id)

        ref = self.identity_api.create_user(user)

        # Test that the user and federated object now exists
        self.assertEqual(user['name'], ref['name'])
        self.assertEqual(user['federated'], ref['federated'])
        fed_user = self.shadow_users_api.get_federated_user(
            self.idp['id'],
            self.protocol['id'],
            unique_id)
        self.assertIsNotNone(fed_user)

    def test_update_user_with_invalid_idp_and_protocol_fails(self):
        baduser = unit.new_user_ref(domain_id=self.domain_id)
        baduser['federated'] = [
            {
                'idp_id': 'fakeidp',
                'protocols': [
                    {
                        'protocol_id': 'nonexistent',
                        'unique_id': 'unknown'
                    }
                ]
            }
        ]
        # Check validation works by throwing a federated object with
        # invalid idp_id, protocol_id inside the user passed to create_user.
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          baduser)

        baduser['federated'][0]['idp_id'] = self.idp['id']
        self.assertRaises(exception.ValidationError,
                          self.identity_api.create_user,
                          baduser)

    def test_update_user_with_federated_attributes(self):
        user = self.shadow_users_api.create_federated_user(
            self.domain_id, self.federated_user)
        user = self.identity_api.get_user(user['id'])

        # Test that update user can return a federated object with the user as
        # a response if the user has any
        user = self.identity_api.update_user(user['id'], user)
        self.assertFederatedDictsEqual(self.federated_user,
                                       user['federated'][0])

        # Test that update user can replace a users federated objects if added
        # in the request and that its response is that new federated objects
        new_fed = [
            {
                'idp_id': self.idp['id'],
                'protocols': [
                    {
                        'protocol_id': self.protocol['id'],
                        'unique_id': uuid.uuid4().hex
                    }
                ]
            }
        ]
        user['federated'] = new_fed
        user = self.identity_api.update_user(user['id'], user)
        self.assertTrue('federated' in user)
        self.assertEqual(len(user['federated']), 1)
        self.assertEqual(user['federated'][0], new_fed[0])

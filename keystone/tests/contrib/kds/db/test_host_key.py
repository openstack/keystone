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

from testscenarios import load_tests_apply_scenarios as load_tests  # noqa

from keystone.contrib.kds.common import exception
from keystone.tests.contrib.kds.db import base

TEST_NAME = 'test-name'
TEST_SIG = 'test-sig'
TEST_KEY = 'test-enc'


class KeyDbTestCase(base.BaseTestCase):

    def test_retrieve(self):
        # Set a key and expect to get the same key back.
        generation = self.DB.set_key(name=TEST_NAME,
                                     signature=TEST_SIG,
                                     key=TEST_KEY,
                                     group=False)
        key = self.DB.get_key(TEST_NAME)

        self.assertEqual(key['name'], TEST_NAME)
        self.assertEqual(key['key'], TEST_KEY)
        self.assertEqual(key['signature'], TEST_SIG)
        self.assertEqual(key['generation'], generation)
        self.assertIs(key['group'], False)
        self.assertIsNone(key['expiration'])

    def test_no_key(self):
        # return None if a key is not in the database
        self.assertIsNone(self.DB.get_key(TEST_NAME))

    def test_generations(self):
        another_key = 'another-key'

        # set a key and make sure that the generation is set and returned
        gen1 = self.DB.set_key(name=TEST_NAME,
                               signature=TEST_SIG,
                               key=TEST_KEY,
                               group=False)

        key1 = self.DB.get_key(TEST_NAME)
        self.assertEqual(key1['key'], TEST_KEY)
        self.assertEqual(key1['generation'], gen1)

        # set a new key for the same name and make sure that the generation is
        # updated
        gen2 = self.DB.set_key(name=TEST_NAME,
                               signature='another-sig',
                               key=another_key,
                               group=False)

        key2 = self.DB.get_key(TEST_NAME)
        self.assertEqual(key2['generation'], gen2)
        self.assertEqual(key2['key'], another_key)

        # Check that if we ask specifically for the first key we get it back
        key3 = self.DB.get_key(TEST_NAME, gen1)
        self.assertEqual(key3['key'], TEST_KEY)
        self.assertEqual(key3['generation'], gen1)

    def test_no_group_filter(self):
        # install a non group key
        generation = self.DB.set_key(name=TEST_NAME,
                                     signature=TEST_SIG,
                                     key=TEST_KEY,
                                     group=False)

        # test that if i can retrieve and specify a non-group key
        key1 = self.DB.get_key(TEST_NAME)
        self.assertEqual(key1['key'], TEST_KEY)
        self.assertEqual(key1['generation'], generation)

        key2 = self.DB.get_key(TEST_NAME, group=False)
        self.assertEqual(key2['key'], TEST_KEY)
        self.assertEqual(key2['generation'], generation)

        # if i ask for a group key of that name then it should fail
        key3 = self.DB.get_key(TEST_NAME, group=True)
        self.assertIsNone(key3)

    def test_with_group_filter(self):
        # install a group key
        generation = self.DB.set_key(name=TEST_NAME,
                                     signature=TEST_SIG,
                                     key=TEST_KEY,
                                     group=True)

        # i should be able to ask for and retrieve a group key
        key1 = self.DB.get_key(TEST_NAME)
        self.assertEqual(key1['key'], TEST_KEY)
        self.assertEqual(key1['generation'], generation)

        key2 = self.DB.get_key(TEST_NAME, group=True)
        self.assertEqual(key2['key'], TEST_KEY)
        self.assertEqual(key2['generation'], generation)

        # if i ask for that key but not a group key it will fail
        key3 = self.DB.get_key(TEST_NAME, group=False)
        self.assertIsNone(key3)

    def test_cant_change_group_status(self):
        group_key_name = 'name1'
        host_key_name = 'name2'

        # install a host and group key
        self.DB.set_key(name=group_key_name,
                        signature=TEST_SIG,
                        key=TEST_KEY,
                        group=True)

        self.DB.set_key(name=host_key_name,
                        signature=TEST_SIG,
                        key=TEST_KEY,
                        group=False)

        # should not be able to change a group key to a host key
        self.assertRaises(exception.IntegrityError, self.DB.set_key,
                          name=group_key_name, signature='xxx', key='xxx',
                          group=False)

        # should not be able to change a host key to a group key
        self.assertRaises(exception.IntegrityError, self.DB.set_key,
                          name=host_key_name, signature='xxx', key='xxx',
                          group=True)

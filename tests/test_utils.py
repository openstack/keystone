# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

# Copyright 2012 Justin Santa Barbara
# All Rights Reserved.
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

import datetime

from keystone import test
from keystone.common import utils


class UtilsTestCase(test.TestCase):
    def test_hash(self):
        password = 'right'
        wrong = 'wrongwrong'  # Two wrongs don't make a right
        hashed = utils.hash_password(password)
        self.assertTrue(utils.check_password(password, hashed))
        self.assertFalse(utils.check_password(wrong, hashed))

    def test_hash_long_password(self):
        bigboy = '0' * 9999999
        hashed = utils.hash_password(bigboy)
        self.assertTrue(utils.check_password(bigboy, hashed))

    def test_hash_edge_cases(self):
        hashed = utils.hash_password('secret')
        self.assertFalse(utils.check_password('', hashed))
        self.assertFalse(utils.check_password(None, hashed))

    def test_hash_unicode(self):
        password = u'Comment \xe7a va'
        wrong = 'Comment ?a va'
        hashed = utils.hash_password(password)
        self.assertTrue(utils.check_password(password, hashed))
        self.assertFalse(utils.check_password(wrong, hashed))

    def test_isotime(self):
        dt = datetime.datetime(year=1987, month=10, day=13,
                               hour=1, minute=2, second=3)
        output = utils.isotime(dt)
        expected = '1987-10-13T01:02:03Z'
        self.assertEqual(output, expected)

    def test_auth_str_equal(self):
        self.assertTrue(utils.auth_str_equal('abc123', 'abc123'))
        self.assertFalse(utils.auth_str_equal('a', 'aaaaa'))
        self.assertFalse(utils.auth_str_equal('aaaaa', 'a'))
        self.assertFalse(utils.auth_str_equal('ABC123', 'abc123'))

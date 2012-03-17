# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest2 as unittest
import keystone.backends.backendutils as backendutils
import keystone.backends as backends


class BackendUtilsTest(unittest.TestCase):

    def setUp(self):
        backends.SHOULD_HASH_PASSWORD = True

    def test_check_long_password(self):
        bigboy = '0' * 9999999
        values = {'password': bigboy}
        backendutils.set_hashed_password(values)
        hashed_pw = values['password']
        self.assertTrue(backendutils.check_password(bigboy, hashed_pw))

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

import datetime
import uuid

from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_serialization import jsonutils

from keystone.common import utils as common_utils
from keystone import exception
from keystone import service
from keystone.tests import unit
from keystone.tests.unit import utils


CONF = cfg.CONF

TZ = utils.TZ


class UtilsTestCase(unit.BaseTestCase):
    OPTIONAL = object()

    def setUp(self):
        super(UtilsTestCase, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))

    def test_hash(self):
        password = 'right'
        wrong = 'wrongwrong'  # Two wrongs don't make a right
        hashed = common_utils.hash_password(password)
        self.assertTrue(common_utils.check_password(password, hashed))
        self.assertFalse(common_utils.check_password(wrong, hashed))

    def test_verify_normal_password_strict(self):
        self.config_fixture.config(strict_password_check=False)
        password = uuid.uuid4().hex
        verified = common_utils.verify_length_and_trunc_password(password)
        self.assertEqual(password, verified)

    def test_that_a_hash_can_not_be_validated_against_a_hash(self):
        # NOTE(dstanek): Bug 1279849 reported a problem where passwords
        # were not being hashed if they already looked like a hash. This
        # would allow someone to hash their password ahead of time
        # (potentially getting around password requirements, like
        # length) and then they could auth with their original password.
        password = uuid.uuid4().hex
        hashed_password = common_utils.hash_password(password)
        new_hashed_password = common_utils.hash_password(hashed_password)
        self.assertFalse(common_utils.check_password(password,
                                                     new_hashed_password))

    def test_verify_long_password_strict(self):
        self.config_fixture.config(strict_password_check=False)
        self.config_fixture.config(group='identity', max_password_length=5)
        max_length = CONF.identity.max_password_length
        invalid_password = 'passw0rd'
        trunc = common_utils.verify_length_and_trunc_password(invalid_password)
        self.assertEqual(invalid_password[:max_length], trunc)

    def test_verify_long_password_strict_raises_exception(self):
        self.config_fixture.config(strict_password_check=True)
        self.config_fixture.config(group='identity', max_password_length=5)
        invalid_password = 'passw0rd'
        self.assertRaises(exception.PasswordVerificationError,
                          common_utils.verify_length_and_trunc_password,
                          invalid_password)

    def test_hash_long_password_truncation(self):
        self.config_fixture.config(strict_password_check=False)
        invalid_length_password = '0' * 9999999
        hashed = common_utils.hash_password(invalid_length_password)
        self.assertTrue(common_utils.check_password(invalid_length_password,
                                                    hashed))

    def test_hash_long_password_strict(self):
        self.config_fixture.config(strict_password_check=True)
        invalid_length_password = '0' * 9999999
        self.assertRaises(exception.PasswordVerificationError,
                          common_utils.hash_password,
                          invalid_length_password)

    def _create_test_user(self, password=OPTIONAL):
        user = {"name": "hthtest"}
        if password is not self.OPTIONAL:
            user['password'] = password

        return user

    def test_hash_user_password_without_password(self):
        user = self._create_test_user()
        hashed = common_utils.hash_user_password(user)
        self.assertEqual(user, hashed)

    def test_hash_user_password_with_null_password(self):
        user = self._create_test_user(password=None)
        hashed = common_utils.hash_user_password(user)
        self.assertEqual(user, hashed)

    def test_hash_user_password_with_empty_password(self):
        password = ''
        user = self._create_test_user(password=password)
        user_hashed = common_utils.hash_user_password(user)
        password_hashed = user_hashed['password']
        self.assertTrue(common_utils.check_password(password, password_hashed))

    def test_hash_edge_cases(self):
        hashed = common_utils.hash_password('secret')
        self.assertFalse(common_utils.check_password('', hashed))
        self.assertFalse(common_utils.check_password(None, hashed))

    def test_hash_unicode(self):
        password = u'Comment \xe7a va'
        wrong = 'Comment ?a va'
        hashed = common_utils.hash_password(password)
        self.assertTrue(common_utils.check_password(password, hashed))
        self.assertFalse(common_utils.check_password(wrong, hashed))

    def test_auth_str_equal(self):
        self.assertTrue(common_utils.auth_str_equal('abc123', 'abc123'))
        self.assertFalse(common_utils.auth_str_equal('a', 'aaaaa'))
        self.assertFalse(common_utils.auth_str_equal('aaaaa', 'a'))
        self.assertFalse(common_utils.auth_str_equal('ABC123', 'abc123'))

    def test_unixtime(self):
        global TZ

        @utils.timezone
        def _test_unixtime():
            epoch = common_utils.unixtime(dt)
            self.assertEqual(epoch, epoch_ans, "TZ=%s" % TZ)

        dt = datetime.datetime(1970, 1, 2, 3, 4, 56, 0)
        epoch_ans = 56 + 4 * 60 + 3 * 3600 + 86400
        for d in ['+0', '-11', '-8', '-5', '+5', '+8', '+14']:
            TZ = 'UTC' + d
            _test_unixtime()

    def test_pki_encoder(self):
        data = {'field': 'value'}
        json = jsonutils.dumps(data, cls=common_utils.PKIEncoder)
        expected_json = '{"field":"value"}'
        self.assertEqual(expected_json, json)


class ServiceHelperTests(unit.BaseTestCase):

    @service.fail_gracefully
    def _do_test(self):
        raise Exception("Test Exc")

    def test_fail_gracefully(self):
        self.assertRaises(unit.UnexpectedExit, self._do_test)

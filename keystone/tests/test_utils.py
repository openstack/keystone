# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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
import functools
import logging
import os
import time
import uuid

from six import moves
from testtools import matchers

from keystone.common import utils
from keystone import tests


TZ = None


def timezone(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tz_original = os.environ.get('TZ')
        try:
            if TZ:
                os.environ['TZ'] = TZ
                time.tzset()
            return func(*args, **kwargs)
        finally:
            if TZ:
                if tz_original:
                    os.environ['TZ'] = tz_original
                else:
                    if 'TZ' in os.environ:
                        del os.environ['TZ']
                time.tzset()
    return wrapper


class UtilsTestCase(tests.TestCase):
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

    def test_auth_str_equal(self):
        self.assertTrue(utils.auth_str_equal('abc123', 'abc123'))
        self.assertFalse(utils.auth_str_equal('a', 'aaaaa'))
        self.assertFalse(utils.auth_str_equal('aaaaa', 'a'))
        self.assertFalse(utils.auth_str_equal('ABC123', 'abc123'))

    def test_unixtime(self):
        global TZ

        @timezone
        def _test_unixtime():
            epoch = utils.unixtime(dt)
            self.assertEqual(epoch, epoch_ans, "TZ=%s" % TZ)

        dt = datetime.datetime(1970, 1, 2, 3, 4, 56, 0)
        epoch_ans = 56 + 4 * 60 + 3 * 3600 + 86400
        for d in ['+0', '-11', '-8', '-5', '+5', '+8', '+14']:
            TZ = 'UTC' + d
            _test_unixtime()


class LimitingReaderTests(tests.TestCase):

    def test_read_default_value(self):

        class FakeData(object):
            def read(self, *args, **kwargs):
                self.read_args = args
                self.read_kwargs = kwargs
                return 'helloworld'

        data = FakeData()
        utils.LimitingReader(data, 100)

        self.assertEqual(data.read(), 'helloworld')
        self.assertEqual(len(data.read_args), 0)
        self.assertEqual(len(data.read_kwargs), 0)

        self.assertEqual(data.read(10), 'helloworld')
        self.assertEqual(len(data.read_args), 1)
        self.assertEqual(len(data.read_kwargs), 0)
        self.assertEqual(data.read_args[0], 10)


class TestDeprecated(tests.TestCase):

    def setUp(self):
        super(TestDeprecated, self).setUp()
        self.deprecated_message = moves.cStringIO()
        self.handler = logging.StreamHandler(self.deprecated_message)
        self.logger = logging.getLogger('keystone.common.utils')
        self.logger.addHandler(self.handler)

    def tearDown(self):
        super(TestDeprecated, self).tearDown()
        self.logger.removeHandler(self.handler)

    def test_deprecating_a_function_returns_correct_value(self):

        @utils.deprecated(as_of=utils.deprecated.ICEHOUSE)
        def do_outdated_stuff(data):
            return data

        expected_rv = uuid.uuid4().hex
        retval = do_outdated_stuff(expected_rv)

        self.assertThat(retval, matchers.Equals(expected_rv))

    def test_deprecating_a_method_returns_correct_value(self):

        class C(object):
            @utils.deprecated(as_of=utils.deprecated.ICEHOUSE)
            def outdated_method(self, *args):
                return args

        retval = C().outdated_method(1, 'of anything')

        self.assertThat(retval, matchers.Equals((1, 'of anything')))

    def test_deprecated_with_unknown_future_release(self):

        @utils.deprecated(as_of=utils.deprecated.ICEHOUSE,
                          in_favor_of='different_stuff()')
        def do_outdated_stuff():
            return

        do_outdated_stuff()

        expected = ('do_outdated_stuff() is deprecated as of Icehouse '
                    'in favor of different_stuff() and may be removed in K.')
        self.assertThat(self.deprecated_message.getvalue(),
                        matchers.Contains(expected))

    def test_deprecated_with_known_future_release(self):

        @utils.deprecated(as_of=utils.deprecated.GRIZZLY,
                          in_favor_of='different_stuff()')
        def do_outdated_stuff():
            return

        do_outdated_stuff()

        expected = ('do_outdated_stuff() is deprecated as of Grizzly '
                    'in favor of different_stuff() and may be removed in '
                    'Icehouse.')
        self.assertThat(self.deprecated_message.getvalue(),
                        matchers.Contains(expected))

    def test_deprecated_without_replacement(self):

        @utils.deprecated(as_of=utils.deprecated.GRIZZLY)
        def do_outdated_stuff():
            return

        do_outdated_stuff()

        expected = ('do_outdated_stuff() is deprecated as of Grizzly '
                    'and may be removed in Icehouse. It will not be '
                    'superseded.')
        self.assertThat(self.deprecated_message.getvalue(),
                        matchers.Contains(expected))

    def test_deprecated_with_custom_what(self):

        @utils.deprecated(as_of=utils.deprecated.GRIZZLY,
                          what='v2.0 API',
                          in_favor_of='v3 API')
        def do_outdated_stuff():
            return

        do_outdated_stuff()

        expected = ('v2.0 API is deprecated as of Grizzly in favor of '
                    'v3 API and may be removed in Icehouse.')
        self.assertThat(self.deprecated_message.getvalue(),
                        matchers.Contains(expected))

    def test_deprecated_with_removed_next_release(self):

        @utils.deprecated(as_of=utils.deprecated.GRIZZLY,
                          remove_in=1)
        def do_outdated_stuff():
            return

        do_outdated_stuff()

        expected = ('do_outdated_stuff() is deprecated as of Grizzly '
                    'and may be removed in Havana. It will not be '
                    'superseded.')
        self.assertThat(self.deprecated_message.getvalue(),
                        matchers.Contains(expected))

    def test_deprecated_with_removed_plus_3(self):

        @utils.deprecated(as_of=utils.deprecated.GRIZZLY,
                          remove_in=+3)
        def do_outdated_stuff():
            return

        do_outdated_stuff()

        expected = ('do_outdated_stuff() is deprecated as of Grizzly '
                    'and may be removed in J. It will not '
                    'be superseded.')
        self.assertThat(self.deprecated_message.getvalue(),
                        matchers.Contains(expected))

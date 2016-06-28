# Copyright 2014 IBM Corp.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import sys
import warnings

from oslo_log import log
from sqlalchemy import exc
from testtools import matchers

from keystone.tests import unit


LOG = log.getLogger(__name__)


class BaseTestTestCase(unit.BaseTestCase):

    def test_unexpected_exit(self):
        # if a test calls sys.exit it raises rather than exiting.
        self.assertThat(lambda: sys.exit(),
                        matchers.raises(unit.UnexpectedExit))


class TestOverrideSkipping(unit.BaseTestCase):

    class TestParent(unit.BaseTestCase):
        def test_in_parent(self):
            pass

    class TestChild(TestParent):
        def test_in_parent(self):
            self.skip_test_overrides('some message')

        def test_not_in_parent(self):
            self.skip_test_overrides('some message')

    def test_skip_test_override_success(self):
        # NOTE(dstanek): let's run the test and see what happens
        test = self.TestChild('test_in_parent')
        result = test.run()

        # NOTE(dstanek): reach into testtools to ensure the test succeeded
        self.assertEqual([], result.decorated.errors)

    def test_skip_test_override_fails_for_missing_parent_test_case(self):
        # NOTE(dstanek): let's run the test and see what happens
        test = self.TestChild('test_not_in_parent')
        result = test.run()

        # NOTE(dstanek): reach into testtools to ensure the test failed
        #                the way we expected
        observed_error = result.decorated.errors[0]
        observed_error_msg = observed_error[1]
        expected_error_msg = ("'test_not_in_parent' is not a previously "
                              "defined test method")
        self.assertIn(expected_error_msg, observed_error_msg)


class TestTestCase(unit.TestCase):

    def test_bad_log(self):
        # If the arguments are invalid for the string in a log it raises an
        # exception during testing.
        self.assertThat(
            lambda: LOG.warning('String %(p1)s %(p2)s', {'p1': 'something'}),
            matchers.raises(KeyError))

    def test_sa_warning(self):
        self.assertThat(
            lambda: warnings.warn('test sa warning error', exc.SAWarning),
            matchers.raises(exc.SAWarning))

    def test_deprecation_warnings_are_raised_as_exceptions_in_tests(self):
        self.assertThat(
            lambda: warnings.warn('this is deprecated', DeprecationWarning),
            matchers.raises(DeprecationWarning))

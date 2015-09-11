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


class TestTestCase(unit.TestCase):

    def test_bad_log(self):
        # If the arguments are invalid for the string in a log it raises an
        # exception during testing.
        self.assertThat(
            lambda: LOG.warn('String %(p1)s %(p2)s', {'p1': 'something'}),
            matchers.raises(KeyError))

    def test_sa_warning(self):
        self.assertThat(
            lambda: warnings.warn('test sa warning error', exc.SAWarning),
            matchers.raises(exc.SAWarning))

    def test_deprecation_warnings_are_raised_as_exceptions_in_tests(self):
        self.assertThat(
            lambda: warnings.warn('this is deprecated', DeprecationWarning),
            matchers.raises(DeprecationWarning))

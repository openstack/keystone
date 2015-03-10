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

from keystone.tests import unit as tests


LOG = log.getLogger(__name__)


class BaseTestTestCase(tests.BaseTestCase):

    def test_unexpected_exit(self):
        # if a test calls sys.exit it raises rather than exiting.
        self.assertThat(lambda: sys.exit(),
                        matchers.raises(tests.UnexpectedExit))


class TestTestCase(tests.TestCase):

    def test_bad_log(self):
        # If the arguments are invalid for the string in a log it raises an
        # exception during testing.
        self.assertThat(
            lambda: LOG.warn('String %(p1)s %(p2)s', {'p1': 'something'}),
            matchers.raises(tests.BadLog))

    def test_sa_warning(self):
        self.assertThat(
            lambda: warnings.warn('test sa warning error', exc.SAWarning),
            matchers.raises(exc.SAWarning))

    def test_deprecations(self):
        # If any deprecation warnings occur during testing it's raised as
        # exception.

        def use_deprecated():
            # DeprecationWarning: BaseException.message has been deprecated as
            # of Python 2.6
            try:
                raise Exception('something')
            except Exception as e:
                e.message

        self.assertThat(use_deprecated, matchers.raises(DeprecationWarning))

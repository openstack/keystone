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

from testtools import matchers

from keystone.openstack.common import log
from keystone import tests


LOG = log.getLogger(__name__)


class TestTestCase(tests.TestCase):
    def test_bad_log(self):
        # If the arguments are invalid for the string in a log it raises an
        # exception during testing.
        self.assertThat(
            lambda: LOG.warn('String %(p1)s %(p2)s', {'p1': 'something'}),
            matchers.raises(tests.BadLog))

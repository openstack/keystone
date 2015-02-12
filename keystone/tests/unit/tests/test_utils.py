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

from testtools import matchers
from testtools import testcase

from keystone.tests.unit import utils


class TestWipDecorator(testcase.TestCase):

    def test_raises_SkipError_when_broken_test_fails(self):

        @utils.wip('waiting on bug #000000')
        def test():
            raise Exception('i expected a failure - this is a WIP')

        e = self.assertRaises(testcase.TestSkipped, test)
        self.assertThat(str(e), matchers.Contains('#000000'))

    def test_raises_AssertionError_when_test_passes(self):

        @utils.wip('waiting on bug #000000')
        def test():
            pass  # literally

        e = self.assertRaises(AssertionError, test)
        self.assertThat(str(e), matchers.Contains('#000000'))

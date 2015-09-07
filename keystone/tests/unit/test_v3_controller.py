# Copyright 2014 CERN.
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

import uuid

import six
from six.moves import range
from testtools import matchers

from keystone.common import controller
from keystone import exception
from keystone.tests import unit


class V3ControllerTestCase(unit.TestCase):
    """Tests for the V3Controller class."""
    def setUp(self):
        super(V3ControllerTestCase, self).setUp()

        class ControllerUnderTest(controller.V3Controller):
            _mutable_parameters = frozenset(['hello', 'world'])

        self.api = ControllerUnderTest()

    def test_check_immutable_params(self):
        """Pass valid parameters to the method and expect no failure."""
        ref = {
            'hello': uuid.uuid4().hex,
            'world': uuid.uuid4().hex
        }
        self.api.check_immutable_params(ref)

    def test_check_immutable_params_fail(self):
        """Pass invalid parameter to the method and expect failure."""
        ref = {uuid.uuid4().hex: uuid.uuid4().hex for _ in range(3)}

        ex = self.assertRaises(exception.ImmutableAttributeError,
                               self.api.check_immutable_params, ref)
        ex_msg = six.text_type(ex)
        self.assertThat(ex_msg, matchers.Contains(self.api.__class__.__name__))
        for key in ref.keys():
            self.assertThat(ex_msg, matchers.Contains(key))

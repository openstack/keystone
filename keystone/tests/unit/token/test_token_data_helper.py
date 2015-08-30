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

import base64
import uuid

from testtools import matchers

from keystone import exception
from keystone.tests import unit
from keystone.token.providers import common


class TestTokenDataHelper(unit.TestCase):
    def setUp(self):
        super(TestTokenDataHelper, self).setUp()
        self.load_backends()
        self.v3_data_helper = common.V3TokenDataHelper()

    def test_v3_token_data_helper_populate_audit_info_string(self):
        token_data = {}
        audit_info = base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2]
        self.v3_data_helper._populate_audit_info(token_data, audit_info)
        self.assertIn(audit_info, token_data['audit_ids'])
        self.assertThat(token_data['audit_ids'], matchers.HasLength(2))

    def test_v3_token_data_helper_populate_audit_info_none(self):
        token_data = {}
        self.v3_data_helper._populate_audit_info(token_data, audit_info=None)
        self.assertThat(token_data['audit_ids'], matchers.HasLength(1))
        self.assertNotIn(None, token_data['audit_ids'])

    def test_v3_token_data_helper_populate_audit_info_list(self):
        token_data = {}
        audit_info = [base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2],
                      base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2]]
        self.v3_data_helper._populate_audit_info(token_data, audit_info)
        self.assertEqual(audit_info, token_data['audit_ids'])

    def test_v3_token_data_helper_populate_audit_info_invalid(self):
        token_data = {}
        audit_info = dict()
        self.assertRaises(exception.UnexpectedError,
                          self.v3_data_helper._populate_audit_info,
                          token_data=token_data,
                          audit_info=audit_info)

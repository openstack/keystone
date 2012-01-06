# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2011 OpenStack, LLC.
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

import json
import logging
import unittest2 as unittest

import base
from keystone.test.unit.decorators import jsonify
from keystone.logic.types import auth

LOGGER = logging.getLogger(__name__)


class PasswordAuthnMethods(base.ServiceAPITest):

    @jsonify
    def test_authn_password_success_json(self):
        """
        Test that good password credentials returns a 200 OK
        """
        url = "/tokens"
        req = self.get_request('POST', url)
        credentials = {
            "username": self.auth_user['name'],
            "password": "auth_pass",
        }
        body = {"auth": {
            "passwordCredentials": credentials,
            "tenantId": self.auth_user['tenant_id'],
            }
        }
        req.body = json.dumps(body)
        self.get_response()

        expected = {
            u'access': {
                u'token': {
                    u'id': self.auth_token_id,
                    u'expires': self.expires.strftime("%Y-%m-%dT%H:%M:%S.%f")},
                u'user': {
                    u'id': unicode(self.auth_user['id']),
                    u'name': self.auth_user['name'],
                    u'roles': [{u'description': u'regular role', u'id': u'0',
                        u'name': u'regular_role'}]}}}

        self.assert_dict_equal(expected, json.loads(self.res.body))
        self.status_ok()


if __name__ == '__main__':
    unittest.main()

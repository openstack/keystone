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
from keystone.logic import signer
from keystone.logic.types import auth

LOGGER = logging.getLogger('test.unit.test_ec2_authn')


class EC2AuthnMethods(base.ServiceAPITest):

    @jsonify
    def test_authn_ec2_success_json(self):
        """
        Test that good ec2 credentials returns a 200 OK
        """
        access = "xpd285.access"
        secret = "345fgi.secret"
        kwargs = {
                  "user_name": self.auth_user['name'],
                  "tenant_id": self.auth_user['tenant_id'],
                  "type": "EC2",
                  "key": access,
                  "secret": secret,
                 }
        self.fixture_create_credentials(**kwargs)
        url = "/ec2tokens"
        req = self.get_request('POST', url)
        params = {
            "SignatureVersion": "2",
            "one_param": "5",
            "two_params": "happy",
        }
        credentials = {
            "access": access,
            "verb": "GET",
            "params": params,
            "host": "some.host.com:8773",
            "path": "services/Cloud",
            "signature": None,
        }
        sign = signer.Signer(secret)
        obj_creds = auth.Ec2Credentials(**credentials)
        credentials['signature'] = sign.generate(obj_creds)
        body = {
            "ec2Credentials": credentials,
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
                    u'roles': []}}}

        self.assert_dict_equal(expected, json.loads(self.res.body))
        self.status_ok()

    @jsonify
    def test_authn_ec2_success_json_bad_user(self):
        """
        Test that bad credentials returns a 401
        """
        access = "xpd285.access"
        secret = "345fgi.secret"
        url = "/ec2tokens"
        req = self.get_request('POST', url)
        params = {
            "SignatureVersion": "2",
            "one_param": "5",
            "two_params": "happy",
        }
        credentials = {
            "access": access,
            "verb": "GET",
            "params": params,
            "host": "some.host.com:8773",
            "path": "services/Cloud",
            "signature": None,
        }
        sign = signer.Signer(secret)
        obj_creds = auth.Ec2Credentials(**credentials)
        credentials['signature'] = sign.generate(obj_creds)
        body = {
            "ec2Credentials": credentials,
        }
        req.body = json.dumps(body)
        self.get_response()

        expected = {
            u'unauthorized': {
                u'code': u'401',
                u'message': u'No credentials found for %s' % access,
            }
        }
        self.assert_dict_equal(expected, json.loads(self.res.body))
        self.assertEqual(self.res.status_int, 401)

    @jsonify
    def test_authn_ec2_success_json_bad_tenant(self):
        """
        Test that bad credentials returns a 401
        """
        access = "xpd285.access"
        secret = "345fgi.secret"
        kwargs = {
                  "user_name": self.auth_user['name'],
                  "tenant_id": 'bad',
                  "type": "EC2",
                  "key": access,
                  "secret": secret,
                 }
        self.fixture_create_credentials(**kwargs)
        url = "/ec2tokens"
        req = self.get_request('POST', url)
        params = {
            "SignatureVersion": "2",
            "one_param": "5",
            "two_params": "happy",
        }
        credentials = {
            "access": access,
            "verb": "GET",
            "params": params,
            "host": "some.host.com:8773",
            "path": "services/Cloud",
            "signature": None,
        }
        sign = signer.Signer(secret)
        obj_creds = auth.Ec2Credentials(**credentials)
        credentials['signature'] = sign.generate(obj_creds)
        body = {
            "ec2Credentials": credentials,
        }
        req.body = json.dumps(body)
        self.get_response()

        expected = {
            u'unauthorized': {
                u'code': u'401',
                u'message': u'Unauthorized on this tenant',
            }
        }
        self.assert_dict_equal(expected, json.loads(self.res.body))
        self.assertEqual(self.res.status_int, 401)


if __name__ == '__main__':
    unittest.main()

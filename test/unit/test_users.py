# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
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


import httplib2
import json
from lxml import etree
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(__file__),
                                '..', '..', '..', '..', 'keystone')))
import unittest

import test_common as utils
from test_common import URL


class UserTest(unittest.TestCase):

    def setUp(self):
        self.tenant = utils.get_tenant()
        self.password = utils.get_password()
        self.email = utils.get_email()
        self.user = utils.get_user()
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.missing_token = utils.get_none_token()
        self.invalid_token = utils.get_non_existing_token()
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.add_user_json(self.tenant, self.user, self.auth_token)
        self.token = utils.get_token(self.user, 'secrete', self.tenant,
                                     'token')

    def tearDown(self):
        utils.delete_user(self.tenant, self.user, str(self.auth_token))


class CreateUserTest(UserTest):

    def test_a_user_create_json(self):

        resp = utils.delete_user(self.tenant, self.user, str(self.auth_token))

        resp, content = utils.create_user(self.tenant, 'test_user1',
                                           str(self.auth_token))
        self.user = 'test_user1'
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(201, resp_val)

    def test_a_user_create_xml(self):
        utils.delete_user_xml(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.create_user_xml(self.tenant, 'test_user1',
                                           str(self.auth_token))
        self.user = 'test_user1'
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(201, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_json_disabled_tenant(self):
        resp, content = utils.create_user('0000', self.user,
                                          str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_create_json_disabled_tenant_xml(self):
        resp, content = utils.create_user_xml('0000', self.user,
                                              str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_again_json(self):
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        self.assertEqual(409, int(resp['status']))

    def test_a_user_create_again_xml(self):
        utils.create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        content = etree.fromstring(content)
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(409, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_email_conflict(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token),
                          self.email)
        resp, content = utils.create_user(self.tenant, self.user,
                                          str(self.auth_token),
                                          self.email)
        self.assertEqual(409, int(resp['status']))

    def test_a_user_create_email_conflict_xml(self):
        utils.create_user_xml(self.tenant,
                              self.user,
                              str(self.auth_token),
                              self.email)
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                              str(self.auth_token),
                                              self.email)
        content = etree.fromstring(content)
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(409, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_expired_token(self):
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.exp_auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, int(resp['status']))

    def test_a_user_create_expired_token_xml(self):
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                              str(self.exp_auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_disabled_token(self):
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.disabled_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, int(resp['status']))

    def test_a_user_create_disabled_token_xml(self):
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                              str(self.disabled_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_missing_token(self):
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.missing_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(401, int(resp['status']))

    def test_a_user_create_missing_token_xml(self):
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                              str(self.missing_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(401, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_create_invalid_token(self):
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.invalid_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(404, int(resp['status']))

    def test_a_user_create_invalid_token_xml(self):
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                        str(self.invalid_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(404, int(resp['status']))
        self.assertEqual('application/xml', utils.content_type(resp))


class GetUserTest(UserTest):

    def test_a_user_get(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json(self.tenant, self.user,
                                            str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(200, resp_val)

    def test_a_user_get_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml(self.tenant, self.user,
                                           str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(200, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_get_expired_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json(self.tenant, self.user,
                                            str(self.exp_auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_expired_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml(self.tenant, self.user,
                                            str(self.exp_auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_get_disabled_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json(self.tenant,
                                            self.user,
                                            str(self.disabled_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_disabled_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml(self.tenant,
                                           self.user,
                                           str(self.disabled_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_get_missing_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json(self.tenant,
                                            self.user,
                                            str(self.missing_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(401, resp_val)

    def test_a_user_get_missing_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml(self.tenant, self.user,
                                           str(self.missing_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_get_invalid_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json(self.tenant, self.user,
                                            str(self.invalid_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(404, resp_val)

    def test_a_user_get_invalid_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml(self.tenant, self.user,
                                           str(self.invalid_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_get_disabled_user(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json(self.tenant,
                                            self.userdisabled,
                                            str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_disabled_user_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml(self.tenant, self.userdisabled,
                                            str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_get_disabled_tenant(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_json('0000', self.user,
                                             str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                                utils.content_type(resp))
        self.assertEqual(403, resp_val)

    def test_a_user_get_disabled_tenant_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_get_xml('0000', self.user,
                                           str(self.auth_token))
        resp_val = int(resp['status'])
        utils.handle_user_resp(self, content, resp_val,
                               utils.content_type(resp))
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml',
                          utils.content_type(resp))


class DeleteUserTest(UserTest):

    def test_a_user_delete(self):
        utils.create_user(self.tenant, self.user,
                          str(self.auth_token))
        resp = utils.delete_user(self.tenant, self.user,
                               str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, resp_val)

    def test_a_user_delete_xml(self):
        utils.create_user(self.tenant, self.user,
                          str(self.auth_token))
        resp = utils.delete_user_xml(self.tenant, self.user,
                                   str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(204, resp_val)

    def test_a_user_delete_expired_token(self):
        utils.create_user(self.tenant, self.user,
                          str(self.auth_token))
        resp = utils.delete_user(self.tenant, self.user,
                               str(self.exp_auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_a_user_delete_expired_token_xml(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user_xml(self.tenant, self.user,
                                    str(self.exp_auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_delete_missing_token(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user(self.tenant, self.user,
                                    str(self.missing_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_a_user_delete_missing_token_xml(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user_xml(self.tenant, self.user,
                                    str(self.missing_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_delete_invalid_token(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user(self.tenant, self.user,
                                    str(self.invalid_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_a_user_delete_invalid_token_xml(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user_xml(self.tenant, self.user,
                                    str(self.invalid_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_a_user_delete_disabled_tenant(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user("0000", self.user,
                                    str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_a_user_delete_disabled_tenant_xml(self):
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        resp = utils.delete_user_xml("0000", self.user,
                                    str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))


class GetUsersTest(UserTest):

    def test_users_get(self):
        resp, content = utils.users_get_json(self.tenant, self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)

    def test_users_get_xml(self):
        resp, content = utils.users_get_xml(self.tenant, self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_get_expired_token(self):
        resp, content = utils.users_get_json(self.tenant, self.exp_auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_get_expired_token_xml(self):
        resp, content = utils.users_get_xml(self.tenant, self.exp_auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_get_disabled_token(self):
        resp, content = utils.users_get_json(self.tenant, self.disabled_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_get_disabled_token_xml(self):
        resp, content = utils.users_get_xml(self.tenant, self.disabled_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_get_missing_token(self):
        resp, content = utils.users_get_json(self.tenant, self.missing_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_users_get_missing_token_xml(self):
        resp, content = utils.users_get_xml(self.tenant, self.missing_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_get_invalid_token(self):
        resp, content = utils.users_get_json(self.tenant, self.invalid_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_users_get_invalid_token_xml(self):
        resp, content = utils.users_get_xml(self.tenant, self.invalid_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_get_disabled_tenant(self):
        resp, content = utils.users_get_json('0000', self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_get_disabled_tenant_xml(self):
        resp, content = utils.users_get_xml('0000', self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))


class GetUsersGroupTest(UserTest):

    def test_users_group_get(self):
        resp, content = utils.users_group_get_json(self.tenant,
                                                   self.user,
                                                   self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)

    def test_users_group_get_xml(self):
        resp, content = utils.users_group_get_xml(self.tenant,
                                                  self.user,
                                                  self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_group_get_expired_token(self):
        resp, content = utils.users_group_get_json(self.tenant,
                                                   self.user,
                                                   self.exp_auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_group_get_expired_token_xml(self):
        resp, content = utils.users_group_get_xml(self.tenant,
                                                  self.user,
                                                  self.exp_auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_group_get_disabled_token(self):
        resp, content = utils.users_group_get_json(self.tenant,
                                                   self.user,
                                                   self.disabled_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_group_get_disabled_token_xml(self):
        resp, content = utils.users_group_get_xml(self.tenant,
                                                  self.user,
                                                  self.disabled_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_group_get_missing_token(self):
        resp, content = utils.users_group_get_json(self.tenant,
                                                   self.user,
                                                   self.missing_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_users_group_get_missing_token_xml(self):
        resp, content = utils.users_group_get_xml(self.tenant,
                                                  self.user,
                                                  self.missing_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_group_get_invalid_token(self):
        resp, content = utils.users_group_get_json(self.tenant,
                                                   self.user,
                                                   self.invalid_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_users_group_get_invalid_token_xml(self):
        resp, content = utils.users_group_get_xml(self.tenant,
                                                  self.user,
                                                  self.invalid_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_users_group_get_disabled_tenant(self):
        resp, content = utils.users_group_get_json('0000',
                                                   self.user,
                                                   self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_users_group_get_disabled_tenant_xml(self):
        resp, content = utils.users_group_get_xml('0000',
                                                  self.user,
                                                  self.auth_token)
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))


class UpdateUserTest(UserTest):

    def test_user_update(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant, self.user,
                                               self.auth_token)
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('updatedjoeuser@rackspace.com',
                         content['user']['email'])

    def test_user_update_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant, self.user,
                                              self.auth_token)
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('updatedjoeuser@rackspace.com',
                          content.get("email"))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_user_disabled(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant,
                                               self.userdisabled,
                                                self.auth_token)
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_update_user_disabled_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant,
                                               self.userdisabled,
                                               self.auth_token)
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_email_conflict(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant,
                                              self.user,
                                              self.auth_token,
                                              "joe@rackspace.com")
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, resp_val)

    def test_user_update_email_conflict_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant,
                                              self.user,
                                              self.auth_token,
                                              "joe@rackspace.com")
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_bad_request_json(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '{"user_bad": { "bad": "updatedjoeuser@rackspace.com"}}'
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)

    def test_user_update_bad_request_xml(self):
        h = httplib2.Http(".cache")
        resp, content = utils.create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                email="updatedjoeuser@rackspace.com" />'
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_expired_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant,
                                              self.user,
                                              self.exp_auth_token)
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_update_expired_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant,
                                             self.user,
                                             self.exp_auth_token)
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_disabled_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant,
                                              self.user,
                                              self.disabled_token)
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_update_disabled_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant,
                                             self.user,
                                             self.disabled_token)
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_invalid_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant,
                                               self.user,
                                               self.invalid_token)
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_user_update_invalid_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant,
                                             self.user,
                                             self.invalid_token)
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_update_missing_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_json(self.tenant,
                                               self.user,
                                               self.missing_token)
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_user_update_missing_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_update_xml(self.tenant,
                                             self.user,
                                             self.missing_token)
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))


class SetPasswordTest(UserTest):

    def test_user_password(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_json(self.tenant,
                                              self.user,
                                              str(self.auth_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('p@ssword', content['user']['password'])

    def test_user_password_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_xml(self.tenant,
                                              self.user,
                                              str(self.auth_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('p@ssword', content.get("password"))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_password_user_disabled(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_json(self.tenant,
                                                self.userdisabled,
                                                str(self.auth_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_password_user_disabled_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_xml(self.tenant,
                                               self.userdisabled,
                                               str(self.auth_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_password_bad_request_json(self):
        h = httplib2.Http(".cache")
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '{"user_bad": { "password": "p@ssword"}}'
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)

    def test_user_password_bad_request_xml(self):
        h = httplib2.Http(".cache")
        utils.create_user_xml(self.tenant, self.user, str(self.auth_token))
        url = '%stenants/%s/users/%s/password' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                password="p@ssword" />'
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_password_expired_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_json(self.tenant,
                                                self.user,
                                                str(self.exp_auth_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_password_expired_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_xml(self.tenant,
                                               self.user,
                                               str(self.exp_auth_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_password_disabled_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_json(self.tenant,
                                                self.user,
                                                str(self.disabled_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_password_disabled_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_xml(self.tenant,
                                                self.user,
                                                str(self.disabled_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_password_invalid_token(self):
        utils.create_user(self.tenant,
                          self.user,
                          str(self.auth_token))
        resp, content = utils.user_password_json(self.tenant,
                                                 self.user,
                                                 str(self.invalid_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_user_password_invalid_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_xml(self.tenant,
                                               self.user,
                                               str(self.invalid_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_password_missing_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_json(self.tenant,
                                                self.user,
                                                str(self.missing_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_user_password_missing_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_password_xml(self.tenant,
                                                self.user,
                                                str(self.missing_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))


class SetEnabledTest(UserTest):

    def test_user_enabled(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_json(self.tenant,
                                                self.user,
                                                str(self.auth_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual(True, content['user']['enabled'])

    def test_user_enabled_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_xml(self.tenant,
                                               self.user,
                                               str(self.auth_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(200, resp_val)
        self.assertEqual('true', content.get("enabled"))
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_enabled_bad_request_json(self):
        h = httplib2.Http(".cache")
        utils.create_user(self.tenant, self.user,
                                    str(self.auth_token))
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '{"user_bad": { "enabled": true}}'
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/json",
                                           "X-Auth-Token": self.auth_token})
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)

    def test_user_enabled_bad_request_xml(self):
        h = httplib2.Http(".cache")
        utils.create_user_xml(self.tenant, self.user,
                                        str(self.auth_token))
        url = '%stenants/%s/users/%s/enabled' % (URL, self.tenant, self.user)
        data = '<?xml version="1.0" encoding="UTF-8"?> \
                user xmlns="http://docs.openstack.org/idm/api/v1.0" \
                enabled="true" />'
        resp, content = h.request(url, "PUT", body=data,
                                  headers={"Content-Type": "application/xml",
                                           "X-Auth-Token": self.auth_token,
                                           "ACCEPT": "application/xml"})
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        self.assertEqual(400, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_enabled_disabled_tenant(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_json('0000',
                                                self.user,
                                                str(self.auth_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_enabled_disabled_tenant_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_xml('0000',
                                               self.user,
                                               str(self.auth_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_enabled_expired_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_json(self.tenant,
                                                self.user,
                                                str(self.exp_auth_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_enabled_expired_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_xml(self.tenant,
                                              self.user,
                                              str(self.exp_auth_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_enabled_disabled_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_json(self.tenant,
                                               self.user,
                                               str(self.disabled_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_user_enabled_disabled_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_xml(self.tenant,
                                               self.user,
                                               str(self.disabled_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_enabled_invalid_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_json(self.tenant,
                                                self.user,
                                                str(self.invalid_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_user_enabled_invalid_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_xml(self.tenant,
                                               self.user,
                                               str(self.invalid_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))

    def test_user_enabled_missing_token(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_json(self.tenant,
                                                self.user,
                                                str(self.missing_token))
        resp_val = int(resp['status'])
        content = json.loads(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_user_enabled_missing_token_xml(self):
        utils.create_user(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.user_enabled_xml(self.tenant,
                                               self.user,
                                               str(self.missing_token))
        resp_val = int(resp['status'])
        content = etree.fromstring(content)
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)
        self.assertEqual('application/xml', utils.content_type(resp))


class AddUserTest(UserTest):

    def setUp(self):
        self.token = utils.get_token('joeuser', 'secrete', 'token')
        self.tenant = utils.get_another_tenant()
        self.password = utils.get_password()
        self.email = utils.get_email()
        self.user = 'joeuser'
        self.userdisabled = utils.get_userdisabled()
        self.auth_token = utils.get_auth_token()
        self.exp_auth_token = utils.get_exp_auth_token()
        self.disabled_token = utils.get_disabled_token()
        self.missing_token = utils.get_none_token()
        self.invalid_token = utils.get_non_existing_token()

    def tearDown(self):
        utils.delete_user(self.tenant, self.user, str(self.auth_token))
        utils.delete_tenant(self.tenant, str(self.auth_token))

    def test_add_user_tenant(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_json(self.tenant,
                                            self.user,
                                            str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)

    def test_add_user_tenant_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_xml(self.tenant,
                                           self.user,
                                           str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(200, resp_val)

    def test_add_user_tenant_conflict(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.add_user_json(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.add_user_json(self.tenant,
                                            self.user,
                                            str(self.auth_token))

        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, resp_val)

    def test_add_user_tenant_conflict_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        utils.add_user_xml(self.tenant, self.user, str(self.auth_token))
        resp, content = utils.add_user_xml(self.tenant,
                                           self.user,
                                           str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(409, resp_val)

    def test_add_user_tenant_expired_token(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_json(self.tenant,
                                            self.user,
                                            str(self.exp_auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_add_user_tenant_expired_token_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_xml(self.tenant,
                                            self.user,
                                            str(self.exp_auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_add_user_tenant_disabled_token(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_json(self.tenant,
                                            self.user,
                                            str(self.disabled_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_add_user_tenant_disabled_token_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_xml(self.tenant,
                                            self.user,
                                            str(self.disabled_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_add_user_tenant_invalid_token(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_json(self.tenant,
                                            self.user,
                                            str(self.invalid_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_add_user_tenant_invalid_token_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_xml(self.tenant,
                                            self.user,
                                            str(self.invalid_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(404, resp_val)

    def test_add_user_tenant_missing_token(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_json(self.tenant,
                                            self.user,
                                            str(self.missing_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_add_user_tenant_missing_token_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_xml(self.tenant,
                                            self.user,
                                            str(self.missing_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(401, resp_val)

    def test_add_user_tenant_disabled_tenant(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_json('0000',
                                            self.user,
                                            str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

    def test_add_user_tenant_disabled_tenant_xml(self):
        utils.create_tenant(self.tenant, str(self.auth_token))
        resp, content = utils.add_user_xml('0000',
                                            self.user,
                                            str(self.auth_token))
        resp_val = int(resp['status'])
        if resp_val == 500:
            self.fail('IDM fault')
        elif resp_val == 503:
            self.fail('Service Not Available')
        self.assertEqual(403, resp_val)

if __name__ == '__main__':
    unittest.main()

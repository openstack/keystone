# Copyright 2016 IBM Corp.
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


import keystone.conf
from keystone import exception
from keystone.identity import controllers
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import database


CONF = keystone.conf.CONF


class UserTestCaseNoDefaultDomain(unit.TestCase):

    def setUp(self):
        super(UserTestCaseNoDefaultDomain, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        self.user_controller = controllers.User()

    def test_setup(self):
        # Other tests in this class assume there's no default domain, so make
        # sure the setUp worked as expected.
        self.assertRaises(
            exception.DomainNotFound,
            self.resource_api.get_domain, CONF.identity.default_domain_id)

    def test_get_users(self):
        # When list_users is done and there's no default domain, the result is
        # an empty list.
        res = self.user_controller.get_users(self.make_request(is_admin=True))
        self.assertEqual([], res['users'])

    def test_get_user_by_name(self):
        # When get_user_by_name is done and there's no default domain, the
        # result is 404 Not Found
        user_name = uuid.uuid4().hex
        self.assertRaises(
            exception.UserNotFound,
            self.user_controller.get_user_by_name,
            self.make_request(is_admin=True), user_name)

    def test_create_user(self):
        # When a user is created using the v2 controller and there's no default
        # domain, it doesn't fail with can't find domain (a default domain is
        # created)
        user = {'name': uuid.uuid4().hex}
        self.user_controller.create_user(self.make_request(is_admin=True),
                                         user)
        # If the above doesn't fail then this is successful.

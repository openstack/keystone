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
from keystone.tests import unit
from keystone.tests.unit import test_v3


CONF = keystone.conf.CONF


class DuplicateTestCase(test_v3.RestfulTestCase):
    def test_domain_duplicate_conflict_gives_name(self):
        domain = unit.new_domain_ref()
        self.resource_api.create_domain(domain['id'], domain)
        domain['id'] = uuid.uuid4().hex
        try:
            self.resource_api.create_domain(domain['id'], domain)
        except exception.Conflict as e:
            self.assertIn("%s" % domain['name'], repr(e))
        else:
            self.fail("Creating duplicate domain did not raise a conflict")

    def test_project_duplicate_conflict_gives_name(self):
        project = unit.new_project_ref(domain_id=self.domain_id)
        self.resource_api.create_project(project['id'], project)
        project['id'] = uuid.uuid4().hex
        try:
            self.resource_api.create_project(project['id'], project)
        except exception.Conflict as e:
            self.assertIn("%s" % project['name'], repr(e))
        else:
            self.fail("Creating duplicate project did not raise a conflict")

    def test_user_duplicate_conflict_gives_name(self):
        user = unit.new_user_ref(domain_id=CONF.identity.default_domain_id)
        user = self.identity_api.create_user(user)
        user['id'] = uuid.uuid4().hex
        try:
            self.identity_api.create_user(user)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s" % user['name'],
                          repr(e))
        else:
            self.fail("Create duplicate user did not raise a conflict")

    def test_role_duplicate_conflict_gives_name(self):
        role = unit.new_role_ref()
        self.role_api.create_role(role['id'], role)
        role['id'] = uuid.uuid4().hex
        try:
            self.role_api.create_role(role['id'], role)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s" % role['name'],
                          repr(e))
        else:
            self.fail("Create duplicate role did not raise a conflict")

    def test_group_duplicate_conflict_gives_name(self):
        group = unit.new_group_ref(domain_id=CONF.identity.default_domain_id)
        group = self.identity_api.create_group(group)
        try:
            self.identity_api.create_group(group)
        except exception.Conflict as e:
            self.assertIn("Duplicate entry found with name %s"
                          % group['name'], repr(e))
        else:
            self.fail("Create duplicate group did not raise a conflict")

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

from oslo_config import cfg

from keystone import exception
from keystone.resource import controllers
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import database


CONF = cfg.CONF

_ADMIN_CONTEXT = {'is_admin': True, 'query_string': {}}


class TenantTestCaseNoDefaultDomain(unit.TestCase):

    def setUp(self):
        super(TenantTestCaseNoDefaultDomain, self).setUp()
        self.useFixture(database.Database())
        self.load_backends()
        self.tenant_controller = controllers.Tenant()

    def test_setup(self):
        # Other tests in this class assume there's no default domain, so make
        # sure the setUp worked as expected.
        self.assertRaises(
            exception.DomainNotFound,
            self.resource_api.get_domain, CONF.identity.default_domain_id)

    def test_get_all_projects(self):
        # When get_all_projects is done and there's no default domain, the
        # result is an empty list.
        res = self.tenant_controller.get_all_projects(_ADMIN_CONTEXT)
        self.assertEqual([], res['tenants'])

    def test_create_project(self):
        # When a project is created using the v2 controller and there's no
        # default domain, it doesn't fail with can't find domain (a default
        # domain is created)
        tenant = {'name': uuid.uuid4().hex}
        self.tenant_controller.create_project(_ADMIN_CONTEXT, tenant)
        # If the above doesn't fail then this is successful.

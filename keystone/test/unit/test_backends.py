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

import os
import unittest2 as unittest
import uuid

from keystone import backends
from keystone import config
from keystone.cfg import OptGroup, NoSuchOptError
import keystone.backends.api as api
import keystone.backends.models as legacy_backend_models
import keystone.backends.sqlalchemy as db
from keystone import models
from keystone.test import KeystoneTest
from keystone import utils

CONF = config.CONF


class BackendTestCase(unittest.TestCase):
    """
    Base class to run tests for Keystone backends (and backend configs)
    """
    def __init__(self, *args, **kwargs):
        super(BackendTestCase, self).__init__(*args, **kwargs)
        self.base_template = "sql.conf.template"
        self.ldap_template = "ldap.conf.template"
        self.current_template = self.base_template

    def setUp(self):
        self.update_CONF(self.current_template)
        db.unregister_models()
        reload(db)
        backends.configure_backends()
        super(BackendTestCase, self).setUp()

    def tearDown(self):
        self.current_template = self.base_template

    def update_CONF(self, template):
        """
        Resets the CONF file, and reads in the passed configuration text.
        """
        kt = KeystoneTest()
        kt.config_name = template
        kt.construct_temp_conf_file()
        fname = kt.conf_fp.name
        # Provide a hook for customizing the config if needed.
        self.modify_conf(fname)
        # Create the configuration
        CONF.reset()
        CONF(config_files=[fname])

    def modify_conf(self, fname):
        pass

    def tearDown(self):
        db.unregister_models()
        reload(db)

    def test_registration(self):
        self.assertIsNotNone(backends.api.CREDENTIALS)
        self.assertIsNotNone(backends.api.ENDPOINT_TEMPLATE)
        self.assertIsNotNone(backends.api.ROLE)
        self.assertIsNotNone(backends.api.SERVICE)
        self.assertIsNotNone(backends.api.TENANT)
        self.assertIsNotNone(backends.api.TOKEN)
        self.assertIsNotNone(backends.api.USER)

    def test_basic_tenant_create(self):
        tenant = models.Tenant(name="Tee One", description="This is T1",
                               enabled=True)

        original_tenant = tenant.copy()
        new_tenant = api.TENANT.create(tenant)
        self.assertIsInstance(new_tenant, models.Tenant)
        for k, v in original_tenant.items():
            if k not in ['id'] and k in new_tenant:
                self.assertEquals(new_tenant[k], v)

    def test_tenant_create_with_id(self):
        tenant = models.Tenant(id="T2%s" % uuid.uuid4().hex, name="Tee Two",
                               description="This is T2", enabled=True)

        original_tenant = tenant.to_dict()
        new_tenant = api.TENANT.create(tenant)
        self.assertIsInstance(new_tenant, models.Tenant)
        for k, v in original_tenant.items():
            if k in new_tenant:
                self.assertEquals(new_tenant[k], v,
                                  "'%s' did not match" % k)
        self.assertEqual(original_tenant['tenant'], tenant,
                         "Backend modified provided tenant")

    def test_tenant_update(self):
        id = "T3%s" % uuid.uuid4().hex
        tenant = models.Tenant(id=id, name="Tee Three",
            description="This is T3", enabled=True)
        new_tenant = api.TENANT.create(tenant)
        new_tenant.enabled = False
        new_tenant.description = "This is UPDATED T3"
        api.TENANT.update(id, new_tenant)
        updated_tenant = api.TENANT.get(id)
        self.assertEqual(new_tenant, updated_tenant)

    def test_endpointtemplate_create(self):
        service = models.Service(name="glance", type="image-service")
        service = api.SERVICE.create(service)

        global_ept = models.EndpointTemplate(
            region="north",
            name="global",
            type=service.type,
            is_global=True,
            public_URL="http://global.public")
        global_ept = api.ENDPOINT_TEMPLATE.create(global_ept)
        self.assertIsNotNone(global_ept.id)

        ept = models.EndpointTemplate(
            region="north",
            name="floating",
            type=service.type,
            is_global=False,
            public_URL="http://floating.public/%tenant_id%/")
        ept = api.ENDPOINT_TEMPLATE.create(ept)
        self.assertIsNotNone(ept.id)

    def test_endpoint_list(self):
        self.test_endpointtemplate_create()
        self.test_basic_tenant_create()
        tenant = api.TENANT.get_by_name("Tee One")

        templates = api.ENDPOINT_TEMPLATE.get_all()
        for template in templates:
            if not template.is_global:
                endpoint = legacy_backend_models.Endpoints()
                endpoint.tenant_id = tenant.id
                endpoint.endpoint_template_id = template.id
                api.ENDPOINT_TEMPLATE.endpoint_add(endpoint)

        global_endpoints = api.TENANT.get_all_endpoints(None)
        self.assertGreater(len(global_endpoints), 0)

        tenant_endpoints = api.TENANT.get_all_endpoints(tenant.id)
        self.assertGreater(len(tenant_endpoints), 0)


class LDAPBackendTestCase(BackendTestCase):
    def setUp(self):
        self.current_template = self.ldap_template
        super(LDAPBackendTestCase, self).setUp()


class SQLiteBackendTestCase(BackendTestCase):
    """ Tests SQLite backend using actual file (not in memory)

    Since we have a code path that is specific to in-memory databases, we need
    to test for when we have a real file behind the ORM
    """
    def setUp(self):
        self.current_template = self.base_template
        self.database_name = os.path.abspath("%s.test.db" % \
                uuid.uuid4().hex)
        super(SQLiteBackendTestCase, self).setUp()

    def modify_conf(self, fname):
        # Need to override the connection
        conn = "sqlite:///%s" % self.database_name
        out = []
        with file(fname, "r") as conf_file:
            for ln in conf_file:
                if ln.rstrip() == "sql_connection = sqlite://":
                    out.append("sql_connection = %s" % conn)
                else:
                    out.append(ln.rstrip())
        with file(fname, "w") as conf_file:
            conf_file.write("\n".join(out))

    def tearDown(self):
        super(SQLiteBackendTestCase, self).tearDown()
        if os.path.exists(self.database_name):
            os.unlink(self.database_name)


if __name__ == '__main__':
    unittest.main()

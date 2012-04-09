# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone import config
from keystone import test
from keystone.common.sql import util as sql_util

import test_keystoneclient


CONF = config.CONF


class KcMasterSqlTestCase(test_keystoneclient.KcMasterTestCase):
    def config(self):
        CONF(config_files=[test.etcdir('keystone.conf.sample'),
                           test.testsdir('test_overrides.conf'),
                           test.testsdir('backend_sql.conf')])
        sql_util.setup_test_database()

    def test_endpoint_crud(self):
        from keystoneclient import exceptions as client_exceptions

        client = self.get_client(admin=True)

        service = client.services.create(name=uuid.uuid4().hex,
                                         service_type=uuid.uuid4().hex,
                                         description=uuid.uuid4().hex)

        endpoint_region = uuid.uuid4().hex
        invalid_service_id = uuid.uuid4().hex
        endpoint_publicurl = uuid.uuid4().hex
        endpoint_internalurl = uuid.uuid4().hex
        endpoint_adminurl = uuid.uuid4().hex

        # a non-existant service ID should trigger a 404
        self.assertRaises(client_exceptions.NotFound,
                          client.endpoints.create,
                          region=endpoint_region,
                          service_id=invalid_service_id,
                          publicurl=endpoint_publicurl,
                          adminurl=endpoint_adminurl,
                          internalurl=endpoint_internalurl)

        endpoint = client.endpoints.create(region=endpoint_region,
                                           service_id=service.id,
                                           publicurl=endpoint_publicurl,
                                           adminurl=endpoint_adminurl,
                                           internalurl=endpoint_internalurl)

        self.assertEquals(endpoint.region, endpoint_region)
        self.assertEquals(endpoint.service_id, service.id)
        self.assertEquals(endpoint.publicurl, endpoint_publicurl)
        self.assertEquals(endpoint.internalurl, endpoint_internalurl)
        self.assertEquals(endpoint.adminurl, endpoint_adminurl)

        client.endpoints.delete(id=endpoint.id)
        self.assertRaises(client_exceptions.NotFound, client.endpoints.delete,
                          id=endpoint.id)

    def test_endpoint_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.endpoints.delete,
                          id=uuid.uuid4().hex)

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

import nose.exc

from keystone.common import sql
from keystone import config
from keystone import test

import test_keystoneclient


CONF = config.CONF


class KcMasterSqlTestCase(test_keystoneclient.KcMasterTestCase, sql.Base):
    def config(self, config_files):
        super(KcMasterSqlTestCase, self).config([
            test.etcdir('keystone.conf.sample'),
            test.testsdir('test_overrides.conf'),
            test.testsdir('backend_sql.conf')])

        self.load_backends()
        self.engine = self.get_engine()
        sql.ModelBase.metadata.create_all(bind=self.engine)

    def tearDown(self):
        sql.ModelBase.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        sql.set_global_engine(None)
        super(KcMasterSqlTestCase, self).tearDown()

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

        # a non-existent service ID should trigger a 404
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

    def test_endpoint_create_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.endpoints.create,
                          region=uuid.uuid4().hex,
                          service_id=uuid.uuid4().hex,
                          publicurl=uuid.uuid4().hex,
                          adminurl=uuid.uuid4().hex,
                          internalurl=uuid.uuid4().hex)

    def test_endpoint_delete_404(self):
        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)
        self.assertRaises(client_exceptions.NotFound,
                          client.endpoints.delete,
                          id=uuid.uuid4().hex)

    def test_policy_crud(self):
        # FIXME(dolph): this test was written prior to the v3 implementation of
        #               the client and essentially refers to a non-existent
        #               policy manager in the v2 client. this test needs to be
        #               moved to a test suite running against the v3 api
        raise nose.exc.SkipTest('Written prior to v3 client; needs refactor')

        from keystoneclient import exceptions as client_exceptions
        client = self.get_client(admin=True)

        policy_blob = uuid.uuid4().hex
        policy_type = uuid.uuid4().hex
        service = client.services.create(
            name=uuid.uuid4().hex,
            service_type=uuid.uuid4().hex,
            description=uuid.uuid4().hex)
        endpoint = client.endpoints.create(
            service_id=service.id,
            region=uuid.uuid4().hex,
            adminurl=uuid.uuid4().hex,
            internalurl=uuid.uuid4().hex,
            publicurl=uuid.uuid4().hex)

        # create
        policy = client.policies.create(
            blob=policy_blob,
            type=policy_type,
            endpoint=endpoint.id)
        self.assertEquals(policy_blob, policy.policy)
        self.assertEquals(policy_type, policy.type)
        self.assertEquals(endpoint.id, policy.endpoint_id)

        policy = client.policies.get(policy=policy.id)
        self.assertEquals(policy_blob, policy.policy)
        self.assertEquals(policy_type, policy.type)
        self.assertEquals(endpoint.id, policy.endpoint_id)

        endpoints = [x for x in client.endpoints.list() if x.id == endpoint.id]
        endpoint = endpoints[0]
        self.assertEquals(policy_blob, policy.policy)
        self.assertEquals(policy_type, policy.type)
        self.assertEquals(endpoint.id, policy.endpoint_id)

        # update
        policy_blob = uuid.uuid4().hex
        policy_type = uuid.uuid4().hex
        endpoint = client.endpoints.create(
            service_id=service.id,
            region=uuid.uuid4().hex,
            adminurl=uuid.uuid4().hex,
            internalurl=uuid.uuid4().hex,
            publicurl=uuid.uuid4().hex)

        policy = client.policies.update(
            policy=policy.id,
            blob=policy_blob,
            type=policy_type,
            endpoint=endpoint.id)

        policy = client.policies.get(policy=policy.id)
        self.assertEquals(policy_blob, policy.policy)
        self.assertEquals(policy_type, policy.type)
        self.assertEquals(endpoint.id, policy.endpoint_id)

        # delete
        client.policies.delete(policy=policy.id)
        self.assertRaises(
            client_exceptions.NotFound,
            client.policies.get,
            policy=policy.id)
        policies = [x for x in client.policies.list() if x.id == policy.id]
        self.assertEquals(len(policies), 0)

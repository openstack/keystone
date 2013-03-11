import uuid

from keystone.common.sql import util as sql_util
from keystone import test

import test_content_types


BASE_URL = 'http://127.0.0.1:35357/v2'


class V2CatalogTestCase(test_content_types.RestfulTestCase):
    def setUp(self):
        super(V2CatalogTestCase, self).setUp()
        self.service_id = uuid.uuid4().hex
        self.service = self.new_service_ref()
        self.service['id'] = self.service_id
        self.catalog_api.create_service(
            self.service_id,
            self.service.copy())

    def new_ref(self):
        """Populates a ref with attributes common to all API entities."""
        return {
            'id': uuid.uuid4().hex,
            'name': uuid.uuid4().hex,
            'description': uuid.uuid4().hex,
            'enabled': True}

    def new_service_ref(self):
        ref = self.new_ref()
        ref['type'] = uuid.uuid4().hex
        return ref

    def _get_token_id(self, r):
        """Applicable only to JSON."""
        return r.body['access']['token']['id']

    def assertValidErrorResponse(self, response):
        self.assertEqual(response.status, 400)

    def _endpoint_create(self, expected_status=200, missing_param=None):
        path = '/v2.0/endpoints'
        body = {
            "endpoint": {
                "adminurl": "http://localhost:8080",
                "service_id": self.service_id,
                "region": "regionOne",
                "internalurl": "http://localhost:8080",
                "publicurl": "http://localhost:8080"
            }
        }
        if missing_param:
            body['endpoint'][missing_param] = None
        r = self.admin_request(method='POST', token=self.get_scoped_token(),
                               path=path, expected_status=expected_status,
                               body=body)
        return body, r

    def test_endpoint_create(self):
        req_body, response = self._endpoint_create(expected_status=200)
        self.assertTrue('endpoint' in response.body)
        self.assertTrue('id' in response.body['endpoint'])
        for field, value in req_body['endpoint'].iteritems():
            self.assertEqual(response.body['endpoint'][field], value)

    def test_endpoint_create_with_missing_adminurl(self):
        req_body, response = self._endpoint_create(expected_status=200,
                                                   missing_param='adminurl')
        self.assertEqual(response.status, 200)

    def test_endpoint_create_with_missing_internalurl(self):
        req_body, response = self._endpoint_create(expected_status=200,
                                                   missing_param='internalurl')
        self.assertEqual(response.status, 200)

    def test_endpoint_create_with_missing_publicurl(self):
        req_body, response = self._endpoint_create(expected_status=400,
                                                   missing_param='publicurl')
        self.assertValidErrorResponse(response)

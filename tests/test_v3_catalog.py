import uuid

import test_v3


class CatalogTestCase(test_v3.RestfulTestCase):
    """Test service & endpoint CRUD"""

    def setUp(self):
        super(CatalogTestCase, self).setUp()

        self.service_id = uuid.uuid4().hex
        self.service = self.new_service_ref()
        self.service['id'] = self.service_id
        self.catalog_api.create_service(
            self.service_id,
            self.service.copy())

        self.endpoint_id = uuid.uuid4().hex
        self.endpoint = self.new_endpoint_ref(service_id=self.service_id)
        self.endpoint['id'] = self.endpoint_id
        self.catalog_api.create_endpoint(
            self.endpoint_id,
            self.endpoint.copy())

    # service crud tests

    def test_create_service(self):
        """POST /services"""
        ref = self.new_service_ref()
        r = self.post(
            '/services',
            body={'service': ref})
        return self.assertValidServiceResponse(r, ref)

    def test_list_services(self):
        """GET /services"""
        r = self.get('/services')
        self.assertValidServiceListResponse(r, ref=self.service)

    def test_list_services_xml(self):
        """GET /services (xml data)"""
        r = self.get('/services', content_type='xml')
        self.assertValidServiceListResponse(r, ref=self.service)

    def test_get_service(self):
        """GET /services/{service_id}"""
        r = self.get('/services/%(service_id)s' % {
            'service_id': self.service_id})
        self.assertValidServiceResponse(r, self.service)

    def test_update_service(self):
        """PATCH /services/{service_id}"""
        service = self.new_service_ref()
        del service['id']
        r = self.patch('/services/%(service_id)s' % {
            'service_id': self.service_id},
            body={'service': service})
        self.assertValidServiceResponse(r, service)

    def test_delete_service(self):
        """DELETE /services/{service_id}"""
        self.delete('/services/%(service_id)s' % {
            'service_id': self.service_id})

    # endpoint crud tests

    def test_list_endpoints(self):
        """GET /endpoints"""
        r = self.get('/endpoints')
        self.assertValidEndpointListResponse(r, ref=self.endpoint)

    def test_list_endpoints_xml(self):
        """GET /endpoints (xml data)"""
        r = self.get('/endpoints', content_type='xml')
        self.assertValidEndpointListResponse(r, ref=self.endpoint)

    def test_create_endpoint(self):
        """POST /endpoints"""
        ref = self.new_endpoint_ref(service_id=self.service_id)
        r = self.post(
            '/endpoints',
            body={'endpoint': ref})
        self.assertValidEndpointResponse(r, ref)

    def assertValidErrorResponse(self, response):
        self.assertTrue(response.status in [400])

    def test_create_endpoint_400(self):
        """POST /endpoints"""
        ref = self.new_endpoint_ref(service_id=self.service_id)
        ref["region"] = "0" * 256
        self.post('/endpoints', body={'endpoint': ref}, expected_status=400)

    def test_get_endpoint(self):
        """GET /endpoints/{endpoint_id}"""
        r = self.get(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id})
        self.assertValidEndpointResponse(r, self.endpoint)

    def test_update_endpoint(self):
        """PATCH /endpoints/{endpoint_id}"""
        ref = self.new_endpoint_ref(service_id=self.service_id)
        del ref['id']
        r = self.patch(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id},
            body={'endpoint': ref})
        self.assertValidEndpointResponse(r, ref)

    def test_delete_endpoint(self):
        """DELETE /endpoints/{endpoint_id}"""
        self.delete(
            '/endpoints/%(endpoint_id)s' % {
                'endpoint_id': self.endpoint_id})

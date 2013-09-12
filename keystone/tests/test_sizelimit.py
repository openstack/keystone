# Copyright (c) 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import webob

from keystone import config
from keystone import exception
from keystone import middleware
from keystone import tests


CONF = config.CONF
MAX_REQUEST_BODY_SIZE = CONF.max_request_body_size


class TestRequestBodySizeLimiter(tests.TestCase):

    def setUp(self):
        super(TestRequestBodySizeLimiter, self).setUp()

        @webob.dec.wsgify()
        def fake_app(req):
            return webob.Response(req.body)

        self.middleware = middleware.RequestBodySizeLimiter(fake_app)
        self.request = webob.Request.blank('/', method='POST')

    def test_content_length_acceptable(self):
        self.request.headers['Content-Length'] = MAX_REQUEST_BODY_SIZE
        self.request.body = "0" * MAX_REQUEST_BODY_SIZE
        response = self.request.get_response(self.middleware)
        self.assertEqual(response.status_int, 200)

    def test_content_length_too_large(self):
        self.request.headers['Content-Length'] = MAX_REQUEST_BODY_SIZE + 1
        self.request.body = "0" * (MAX_REQUEST_BODY_SIZE + 1)
        self.assertRaises(exception.RequestTooLarge,
                          self.request.get_response,
                          self.middleware)

    def test_request_too_large_no_content_length(self):
        self.request.body = "0" * (MAX_REQUEST_BODY_SIZE + 1)
        self.request.headers['Content-Length'] = None
        self.assertRaises(exception.RequestTooLarge,
                          self.request.get_response,
                          self.middleware)

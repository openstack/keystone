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

import json

import webob

from keystone import config
from keystone import middleware
from keystone import test


CONF = config.CONF


def make_request(**kwargs):
    accept = kwargs.pop('accept', None)
    method = kwargs.pop('method', 'GET')
    body = kwargs.pop('body', None)
    req = webob.Request.blank('/', **kwargs)
    req.method = method
    if body is not None:
        req.body = body
    if accept is not None:
        req.accept = accept
    return req


def make_response(**kwargs):
    body = kwargs.pop('body', None)
    return webob.Response(body)


class TokenAuthMiddlewareTest(test.TestCase):
    def test_request(self):
        req = make_request()
        req.headers[middleware.AUTH_TOKEN_HEADER] = 'MAGIC'
        middleware.TokenAuthMiddleware(None).process_request(req)
        context = req.environ[middleware.CONTEXT_ENV]
        self.assertEqual(context['token_id'], 'MAGIC')


class AdminTokenAuthMiddlewareTest(test.TestCase):
    def test_request_admin(self):
        req = make_request()
        req.headers[middleware.AUTH_TOKEN_HEADER] = CONF.admin_token
        middleware.AdminTokenAuthMiddleware(None).process_request(req)
        context = req.environ[middleware.CONTEXT_ENV]
        self.assertTrue(context['is_admin'])

    def test_request_non_admin(self):
        req = make_request()
        req.headers[middleware.AUTH_TOKEN_HEADER] = 'NOT-ADMIN'
        middleware.AdminTokenAuthMiddleware(None).process_request(req)
        context = req.environ[middleware.CONTEXT_ENV]
        self.assertFalse(context['is_admin'])


class PostParamsMiddlewareTest(test.TestCase):
    def test_request_with_params(self):
        req = make_request(body="arg1=one", method='POST')
        middleware.PostParamsMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(params, {"arg1": "one"})


class JsonBodyMiddlewareTest(test.TestCase):
    def test_request_with_params(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           content_type='application/json',
                           method='POST')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(params, {"arg1": "one", "arg2": ["a"]})

    def test_malformed_json(self):
        req = make_request(body='{"arg1": "on',
                           content_type='application/json',
                           method='POST')
        _middleware = middleware.JsonBodyMiddleware(None)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          _middleware.process_request, req)

    def test_no_content_type(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           method='POST')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(params, {"arg1": "one", "arg2": ["a"]})

    def test_unrecognized_content_type(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           content_type='text/plain',
                           method='POST')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ.get(middleware.PARAMS_ENV, {})
        self.assertEqual(params, {})


class XmlBodyMiddlewareTest(test.TestCase):
    def test_client_wants_xml_back(self):
        """Clients requesting XML should get what they ask for."""
        body = '{"container": {"attribute": "value"}}'
        req = make_request(body=body, method='POST', accept='application/xml')
        middleware.XmlBodyMiddleware(None).process_request(req)
        resp = make_response(body=body)
        middleware.XmlBodyMiddleware(None).process_response(req, resp)
        self.assertEqual(resp.content_type, 'application/xml')

    def test_client_wants_json_back(self):
        """Clients requesting JSON should definitely not get XML back."""
        body = '{"container": {"attribute": "value"}}'
        req = make_request(body=body, method='POST', accept='application/json')
        middleware.XmlBodyMiddleware(None).process_request(req)
        resp = make_response(body=body)
        middleware.XmlBodyMiddleware(None).process_response(req, resp)
        self.assertNotIn('application/xml', resp.content_type)

    def test_client_fails_to_specify_accept(self):
        """If client does not specify an Accept header, default to JSON."""
        body = '{"container": {"attribute": "value"}}'
        req = make_request(body=body, method='POST')
        middleware.XmlBodyMiddleware(None).process_request(req)
        resp = make_response(body=body)
        middleware.XmlBodyMiddleware(None).process_response(req, resp)
        self.assertNotIn('application/xml', resp.content_type)

    def test_xml_replaced_by_json(self):
        """XML requests should be replaced by JSON requests."""
        req = make_request(
                body='<container><element attribute="value" /></container>',
                content_type='application/xml',
                method='POST')
        middleware.XmlBodyMiddleware(None).process_request(req)
        self.assertTrue(req.content_type, 'application/json')
        self.assertTrue(json.loads(req.body))

    def test_json_unnaffected(self):
        """JSON-only requests should be unnaffected by the XML middleware."""
        content_type = 'application/json'
        body = '{"container": {"attribute": "value"}}'
        req = make_request(body=body, content_type=content_type, method='POST')
        middleware.XmlBodyMiddleware(None).process_request(req)
        self.assertEqual(req.body, body)
        self.assertEqual(req.content_type, content_type)

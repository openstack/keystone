# vim: tabstop=4 shiftwidth=4 softtabstop=4

import webob

from keystone import config
from keystone import middleware
from keystone import test


CONF = config.CONF


def make_request(**kwargs):
    return webob.Request.blank('/', **kwargs)


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
        req = make_request(POST={"arg1": "one"})
        middleware.PostParamsMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(params, {"arg1": "one"})


class JsonBodyMiddlewareTest(test.TestCase):
    def test_request_with_params(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           content_type='application/json')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(params, {"arg1": "one", "arg2": ["a"]})

    def test_malformed_json(self):
        req = make_request(body='{"arg1": "on',
                           content_type='application/json')
        _middleware = middleware.JsonBodyMiddleware(None)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          _middleware.process_request, req)

    def test_no_content_type(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(params, {"arg1": "one", "arg2": ["a"]})

    def test_unrecognized_content_type(self):
        req = make_request(body='{"arg1": "one", "arg2": ["a"]}',
                           content_type='text/plain')
        middleware.JsonBodyMiddleware(None).process_request(req)
        params = req.environ.get(middleware.PARAMS_ENV, {})
        self.assertEqual(params, {})

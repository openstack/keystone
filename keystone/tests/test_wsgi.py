# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

from babel import localedata
import gettext

from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common import gettextutils
from keystone.openstack.common import jsonutils
from keystone import tests


class FakeApp(wsgi.Application):
    def index(self, context):
        return {'a': 'b'}


class BaseWSGITest(tests.TestCase):
    def setUp(self):
        self.app = FakeApp()
        super(BaseWSGITest, self).setUp()

    def _make_request(self, url='/'):
        req = wsgi.Request.blank(url)
        args = {'action': 'index', 'controller': None}
        req.environ['wsgiorg.routing_args'] = [None, args]
        return req


class ApplicationTest(BaseWSGITest):
    def test_response_content_type(self):
        req = self._make_request()
        resp = req.get_response(self.app)
        self.assertEqual(resp.content_type, 'application/json')

    def test_query_string_available(self):
        class FakeApp(wsgi.Application):
            def index(self, context):
                return context['query_string']
        req = self._make_request(url='/?1=2')
        resp = req.get_response(FakeApp())
        self.assertEqual(jsonutils.loads(resp.body), {'1': '2'})

    def test_headers_available(self):
        class FakeApp(wsgi.Application):
            def index(self, context):
                return context['headers']

        app = FakeApp()
        req = self._make_request(url='/?1=2')
        req.headers['X-Foo'] = "bar"
        resp = req.get_response(app)
        self.assertIn('X-Foo', eval(resp.body))

    def test_render_response(self):
        data = {'attribute': 'value'}
        body = '{"attribute": "value"}'

        resp = wsgi.render_response(body=data)
        self.assertEqual(resp.status, '200 OK')
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.body, body)
        self.assertEqual(resp.headers.get('Vary'), 'X-Auth-Token')
        self.assertEqual(resp.headers.get('Content-Length'), str(len(body)))

    def test_render_response_custom_status(self):
        resp = wsgi.render_response(status=(501, 'Not Implemented'))
        self.assertEqual(resp.status, '501 Not Implemented')
        self.assertEqual(resp.status_int, 501)

    def test_render_response_custom_headers(self):
        resp = wsgi.render_response(headers=[('Custom-Header', 'Some-Value')])
        self.assertEqual(resp.headers.get('Custom-Header'), 'Some-Value')
        self.assertEqual(resp.headers.get('Vary'), 'X-Auth-Token')

    def test_render_response_no_body(self):
        resp = wsgi.render_response()
        self.assertEqual(resp.status, '204 No Content')
        self.assertEqual(resp.status_int, 204)
        self.assertEqual(resp.body, '')
        self.assertEqual(resp.headers.get('Content-Length'), '0')
        self.assertEqual(resp.headers.get('Content-Type'), None)

    def test_application_local_config(self):
        class FakeApp(wsgi.Application):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        app = FakeApp.factory({}, testkey="test")
        self.assertIn("testkey", app.kwargs)
        self.assertEquals("test", app.kwargs["testkey"])

    def test_render_exception(self):
        e = exception.Unauthorized(message=u'\u7f51\u7edc')
        resp = wsgi.render_exception(e)
        self.assertEqual(resp.status_int, 401)


class ExtensionRouterTest(BaseWSGITest):
    def test_extensionrouter_local_config(self):
        class FakeRouter(wsgi.ExtensionRouter):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeRouter.factory({}, testkey="test")
        app = factory(self.app)
        self.assertIn("testkey", app.kwargs)
        self.assertEquals("test", app.kwargs["testkey"])


class MiddlewareTest(BaseWSGITest):
    def test_middleware_request(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_request(self, req):
                req.environ['fake_request'] = True
                return req
        req = self._make_request()
        resp = FakeMiddleware(None)(req)
        self.assertIn('fake_request', resp.environ)

    def test_middleware_response(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                response.environ = {}
                response.environ['fake_response'] = True
                return response
        req = self._make_request()
        resp = FakeMiddleware(self.app)(req)
        self.assertIn('fake_response', resp.environ)

    def test_middleware_bad_request(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise exception.Unauthorized()

        req = self._make_request()
        req.environ['REMOTE_ADDR'] = '127.0.0.1'
        resp = FakeMiddleware(self.app)(req)
        self.assertEquals(resp.status_int, exception.Unauthorized.code)

    def test_middleware_type_error(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise TypeError()

        req = self._make_request()
        req.environ['REMOTE_ADDR'] = '127.0.0.1'
        resp = FakeMiddleware(self.app)(req)
        # This is a validationerror type
        self.assertEquals(resp.status_int, exception.ValidationError.code)

    def test_middleware_exception_error(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise exception.UnexpectedError("EXCEPTIONERROR")

        req = self._make_request()
        resp = FakeMiddleware(self.app)(req)
        self.assertEquals(resp.status_int, exception.UnexpectedError.code)
        self.assertIn("EXCEPTIONERROR", resp.body)

    def test_middleware_local_config(self):
        class FakeMiddleware(wsgi.Middleware):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeMiddleware.factory({}, testkey="test")
        app = factory(self.app)
        self.assertIn("testkey", app.kwargs)
        self.assertEquals("test", app.kwargs["testkey"])


class WSGIFunctionTest(tests.TestCase):
    def test_mask_password(self):
        message = ("test = 'password': 'aaaaaa', 'param1': 'value1', "
                   "\"new_password\": 'bbbbbb'")
        self.assertEqual(wsgi.mask_password(message, True),
                         u"test = 'password': '***', 'param1': 'value1', "
                         "\"new_password\": '***'")

        message = "test = 'password'  :   'aaaaaa'"
        self.assertEqual(wsgi.mask_password(message, False, '111'),
                         "test = 'password'  :   '111'")

        message = u"test = u'password' : u'aaaaaa'"
        self.assertEqual(wsgi.mask_password(message, True),
                         u"test = u'password' : u'***'")

        message = 'test = "password" : "aaaaaaaaa"'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "password" : "***"')

        message = 'test = "original_password" : "aaaaaaaaa"'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "original_password" : "***"')

        message = 'test = "original_password" : ""'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "original_password" : "***"')

        message = 'test = "param1" : "value"'
        self.assertEqual(wsgi.mask_password(message),
                         'test = "param1" : "value"')


class LocalizedResponseTest(tests.TestCase):
    def setUp(self):
        super(LocalizedResponseTest, self).setUp()
        gettextutils._AVAILABLE_LANGUAGES.clear()

    def tearDown(self):
        gettextutils._AVAILABLE_LANGUAGES.clear()
        super(LocalizedResponseTest, self).tearDown()

    def _set_expected_languages(self, all_locales=[], avail_locales=None):
        # Override localedata.locale_identifiers to return some locales.
        def returns_some_locales(*args, **kwargs):
            return all_locales

        self.stubs.Set(localedata, 'locale_identifiers', returns_some_locales)

        # Override gettext.find to return other than None for some languages.
        def fake_gettext_find(lang_id, *args, **kwargs):
            found_ret = '/keystone/%s/LC_MESSAGES/keystone.mo' % lang_id
            if avail_locales is None:
                # All locales are available.
                return found_ret
            languages = kwargs['languages']
            if languages[0] in avail_locales:
                return found_ret
            return None

        self.stubs.Set(gettext, 'find', fake_gettext_find)

    def test_request_match_default(self):
        # The default language if no Accept-Language is provided is None
        req = wsgi.Request.blank('/')
        self.assertIsNone(req.best_match_language())

    def test_request_match_language_expected(self):
        # If Accept-Language is a supported language, best_match_language()
        # returns it.

        self._set_expected_languages(all_locales=['it'])

        req = wsgi.Request.blank('/', headers={'Accept-Language': 'it'})
        self.assertEquals(req.best_match_language(), 'it')

    def test_request_match_language_unexpected(self):
        # If Accept-Language is a language we do not support,
        # best_match_language() returns None.

        self._set_expected_languages(all_locales=['it'])

        req = wsgi.Request.blank('/', headers={'Accept-Language': 'zh'})
        self.assertIsNone(req.best_match_language())

    def test_localized_message(self):
        # If the accept-language header is set on the request, the localized
        # message is returned by calling get_localized_message.

        LANG_ID = uuid.uuid4().hex
        ORIGINAL_TEXT = uuid.uuid4().hex
        TRANSLATED_TEXT = uuid.uuid4().hex

        self._set_expected_languages(all_locales=[LANG_ID])

        def fake_get_localized_message(message, user_locale):
            if (user_locale == LANG_ID and
                    message == ORIGINAL_TEXT):
                return TRANSLATED_TEXT

        self.stubs.Set(gettextutils, 'get_localized_message',
                       fake_get_localized_message)

        error = exception.NotFound(message=ORIGINAL_TEXT)
        resp = wsgi.render_exception(error, user_locale=LANG_ID)
        result = jsonutils.loads(resp.body)

        exp = {'error': {'message': TRANSLATED_TEXT,
                         'code': 404,
                         'title': 'Not Found'}}

        self.assertEqual(exp, result)

    def test_static_translated_string_is_Message(self):
        # Statically created message strings are Message objects so that they
        # are lazy-translated.
        self.assertIsInstance(exception.Unauthorized.message_format,
                              gettextutils.Message)

    def test_dynamic_translated_string_is_Message(self):
        # Dynamically created message strings are Message objects so that they
        # are lazy-translated.
        self.assertIsInstance(_('The resource could not be found.'),
                              gettextutils.Message)

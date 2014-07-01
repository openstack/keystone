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

import gettext
import socket
import uuid

from babel import localedata
import mock
import webob

from keystone.common import environment
from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common.fixture import moxstubout
from keystone.openstack.common import gettextutils
from keystone.openstack.common.gettextutils import _
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
        req = webob.Request.blank(url)
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

    def test_render_response_head_with_body(self):
        resp = wsgi.render_response({'id': uuid.uuid4().hex}, method='HEAD')
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.body, b'')
        self.assertNotEqual(resp.headers.get('Content-Length'), '0')
        self.assertEqual(resp.headers.get('Content-Type'), 'application/json')

    def test_application_local_config(self):
        class FakeApp(wsgi.Application):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        app = FakeApp.factory({}, testkey="test")
        self.assertIn("testkey", app.kwargs)
        self.assertEqual("test", app.kwargs["testkey"])

    def test_render_exception(self):
        e = exception.Unauthorized(message=u'\u7f51\u7edc')
        resp = wsgi.render_exception(e)
        self.assertEqual(resp.status_int, 401)

    def test_render_exception_host(self):
        e = exception.Unauthorized(message=u'\u7f51\u7edc')
        context = {'host_url': 'http://%s:5000' % uuid.uuid4().hex}
        resp = wsgi.render_exception(e, context=context)

        self.assertEqual(resp.status_int, 401)


class ExtensionRouterTest(BaseWSGITest):
    def test_extensionrouter_local_config(self):
        class FakeRouter(wsgi.ExtensionRouter):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeRouter.factory({}, testkey="test")
        app = factory(self.app)
        self.assertIn("testkey", app.kwargs)
        self.assertEqual("test", app.kwargs["testkey"])


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
        self.assertEqual(resp.status_int, exception.Unauthorized.code)

    def test_middleware_type_error(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise TypeError()

        req = self._make_request()
        req.environ['REMOTE_ADDR'] = '127.0.0.1'
        resp = FakeMiddleware(self.app)(req)
        # This is a validationerror type
        self.assertEqual(resp.status_int, exception.ValidationError.code)

    def test_middleware_exception_error(self):

        exception_str = 'EXCEPTIONERROR'

        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise exception.UnexpectedError(exception_str)

        def do_request():
            req = self._make_request()
            resp = FakeMiddleware(self.app)(req)
            self.assertEqual(resp.status_int, exception.UnexpectedError.code)
            return resp

        # Exception data should not be in the message when debug is False
        self.config_fixture.config(debug=False)
        self.assertNotIn(exception_str, do_request().body)

        # Exception data should be in the message when debug is True
        self.config_fixture.config(debug=True)
        self.assertIn(exception_str, do_request().body)

    def test_middleware_local_config(self):
        class FakeMiddleware(wsgi.Middleware):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeMiddleware.factory({}, testkey="test")
        app = factory(self.app)
        self.assertIn("testkey", app.kwargs)
        self.assertEqual("test", app.kwargs["testkey"])


class LocalizedResponseTest(tests.TestCase):
    def setUp(self):
        super(LocalizedResponseTest, self).setUp()

        gettextutils._AVAILABLE_LANGUAGES.clear()
        self.addCleanup(gettextutils._AVAILABLE_LANGUAGES.clear)

        fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = fixture.stubs

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
        req = webob.Request.blank('/')
        self.assertIsNone(wsgi.best_match_language(req))

    def test_request_match_language_expected(self):
        # If Accept-Language is a supported language, best_match_language()
        # returns it.

        self._set_expected_languages(all_locales=['it'])

        req = webob.Request.blank('/', headers={'Accept-Language': 'it'})
        self.assertEqual(wsgi.best_match_language(req), 'it')

    def test_request_match_language_unexpected(self):
        # If Accept-Language is a language we do not support,
        # best_match_language() returns None.

        self._set_expected_languages(all_locales=['it'])

        req = webob.Request.blank('/', headers={'Accept-Language': 'zh'})
        self.assertIsNone(wsgi.best_match_language(req))

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


class ServerTest(tests.TestCase):

    def setUp(self):
        super(ServerTest, self).setUp()
        environment.use_eventlet()
        self.host = '127.0.0.1'
        self.port = '1234'

    @mock.patch('eventlet.listen')
    @mock.patch('socket.getaddrinfo')
    def test_keepalive_unset(self, mock_getaddrinfo, mock_listen):
        mock_getaddrinfo.return_value = [(1, 2, 3, 4, 5)]
        mock_sock = mock.Mock()
        mock_sock.setsockopt = mock.Mock()

        mock_listen.return_value = mock_sock
        server = environment.Server(mock.MagicMock(), host=self.host,
                                    port=self.port)
        server.start()
        self.assertTrue(mock_listen.called)
        self.assertFalse(mock_sock.setsockopt.called)

    @mock.patch('eventlet.listen')
    @mock.patch('socket.getaddrinfo')
    def test_keepalive_set(self, mock_getaddrinfo, mock_listen):
        mock_getaddrinfo.return_value = [(1, 2, 3, 4, 5)]
        mock_sock = mock.Mock()
        mock_sock.setsockopt = mock.Mock()

        mock_listen.return_value = mock_sock
        server = environment.Server(mock.MagicMock(), host=self.host,
                                    port=self.port, keepalive=True)
        server.start()
        mock_sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET,
                                                     socket.SO_KEEPALIVE,
                                                     1)
        self.assertTrue(mock_listen.called)

    @mock.patch('eventlet.listen')
    @mock.patch('socket.getaddrinfo')
    def test_keepalive_and_keepidle_set(self, mock_getaddrinfo, mock_listen):
        mock_getaddrinfo.return_value = [(1, 2, 3, 4, 5)]
        mock_sock = mock.Mock()
        mock_sock.setsockopt = mock.Mock()

        mock_listen.return_value = mock_sock
        server = environment.Server(mock.MagicMock(), host=self.host,
                                    port=self.port, keepalive=True,
                                    keepidle=1)
        server.start()

        # keepidle isn't available in the OS X version of eventlet
        if hasattr(socket, 'TCP_KEEPIDLE'):
            self.assertEqual(mock_sock.setsockopt.call_count, 2)

            # Test the last set of call args i.e. for the keepidle
            mock_sock.setsockopt.assert_called_with(socket.IPPROTO_TCP,
                                                    socket.TCP_KEEPIDLE,
                                                    1)
        else:
            self.assertEqual(mock_sock.setsockopt.call_count, 1)

        self.assertTrue(mock_listen.called)

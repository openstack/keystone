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

import mock
from oslo import i18n
import six
from testtools import matchers
import webob

from keystone.common import environment
from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone import tests


class FakeApp(wsgi.Application):
    def index(self, context):
        return {'a': 'b'}


class FakeAttributeCheckerApp(wsgi.Application):
    def index(self, context):
        return context['query_string']

    def assert_attribute(self, body, attr):
        """Asserts that the given request has a certain attribute."""
        ref = jsonutils.loads(body)
        self._require_attribute(ref, attr)

    def assert_attributes(self, body, attr):
        """Asserts that the given request has a certain set attributes."""
        ref = jsonutils.loads(body)
        self._require_attributes(ref, attr)


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
        body = b'{"attribute": "value"}'

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

    def test_successful_require_attribute(self):
        app = FakeAttributeCheckerApp()
        req = self._make_request(url='/?1=2')
        resp = req.get_response(app)
        app.assert_attribute(resp.body, '1')

    def test_require_attribute_fail_if_attribute_not_present(self):
        app = FakeAttributeCheckerApp()
        req = self._make_request(url='/?1=2')
        resp = req.get_response(app)
        self.assertRaises(exception.ValidationError,
                          app.assert_attribute, resp.body, 'a')

    def test_successful_require_multiple_attributes(self):
        app = FakeAttributeCheckerApp()
        req = self._make_request(url='/?a=1&b=2')
        resp = req.get_response(app)
        app.assert_attributes(resp.body, ['a', 'b'])

    def test_attribute_missing_from_request(self):
        app = FakeAttributeCheckerApp()
        req = self._make_request(url='/?a=1&b=2')
        resp = req.get_response(app)
        ex = self.assertRaises(exception.ValidationError,
                               app.assert_attributes,
                               resp.body, ['a', 'missing_attribute'])
        self.assertThat(six.text_type(ex),
                        matchers.Contains('missing_attribute'))

    def test_no_required_attributes_present(self):
        app = FakeAttributeCheckerApp()
        req = self._make_request(url='/')
        resp = req.get_response(app)

        ex = self.assertRaises(exception.ValidationError,
                               app.assert_attributes, resp.body,
                               ['missing_attribute1', 'missing_attribute2'])
        self.assertThat(six.text_type(ex),
                        matchers.Contains('missing_attribute1'))
        self.assertThat(six.text_type(ex),
                        matchers.Contains('missing_attribute2'))

    def test_render_response_custom_headers(self):
        resp = wsgi.render_response(headers=[('Custom-Header', 'Some-Value')])
        self.assertEqual(resp.headers.get('Custom-Header'), 'Some-Value')
        self.assertEqual(resp.headers.get('Vary'), 'X-Auth-Token')

    def test_render_response_no_body(self):
        resp = wsgi.render_response()
        self.assertEqual(resp.status, '204 No Content')
        self.assertEqual(resp.status_int, 204)
        self.assertEqual(resp.body, b'')
        self.assertEqual(resp.headers.get('Content-Length'), '0')
        self.assertIsNone(resp.headers.get('Content-Type'))

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

        exception_str = b'EXCEPTIONERROR'

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
    def test_request_match_default(self):
        # The default language if no Accept-Language is provided is None
        req = webob.Request.blank('/')
        self.assertIsNone(wsgi.best_match_language(req))

    @mock.patch.object(i18n, 'get_available_languages')
    def test_request_match_language_expected(self, mock_gal):
        # If Accept-Language is a supported language, best_match_language()
        # returns it.

        language = uuid.uuid4().hex
        mock_gal.return_value = [language]

        req = webob.Request.blank('/', headers={'Accept-Language': language})
        self.assertEqual(wsgi.best_match_language(req), language)

    @mock.patch.object(i18n, 'get_available_languages')
    def test_request_match_language_unexpected(self, mock_gal):
        # If Accept-Language is a language we do not support,
        # best_match_language() returns None.

        supported_language = uuid.uuid4().hex
        mock_gal.return_value = [supported_language]

        request_language = uuid.uuid4().hex
        req = webob.Request.blank(
            '/', headers={'Accept-Language': request_language})
        self.assertIsNone(wsgi.best_match_language(req))

    def test_static_translated_string_is_lazy_translatable(self):
        # Statically created message strings are an object that can get
        # lazy-translated rather than a regular string.
        self.assertNotEqual(type(exception.Unauthorized.message_format),
                            six.text_type)

    @mock.patch.object(i18n, 'get_available_languages')
    def test_get_localized_response(self, mock_gal):
        # If the request has the Accept-Language set to a supported language
        # and an exception is raised by the application that is translatable
        # then the response will have the translated message.

        language = uuid.uuid4().hex
        mock_gal.return_value = [language]

        # The arguments for the xlated message format have to match the args
        # for the chosen exception (exception.NotFound)
        xlated_msg_fmt = "Xlated NotFound, %(target)s."

        # Fake out gettext.translation() to return a translator for our
        # expected language and a passthrough translator for other langs.

        def fake_translation(*args, **kwargs):
            class IdentityTranslator(object):
                def ugettext(self, msgid):
                    return msgid

                gettext = ugettext

            class LangTranslator(object):
                def ugettext(self, msgid):
                    if msgid == exception.NotFound.message_format:
                        return xlated_msg_fmt
                    return msgid

                gettext = ugettext

            if language in kwargs.get('languages', []):
                return LangTranslator()
            return IdentityTranslator()

        with mock.patch.object(gettext, 'translation',
                               side_effect=fake_translation) as xlation_mock:
            target = uuid.uuid4().hex

            # Fake app raises NotFound exception to simulate Keystone raising.

            class FakeApp(wsgi.Application):
                def index(self, context):
                    raise exception.NotFound(target=target)

            # Make the request with Accept-Language on the app, expect an error
            # response with the translated message.

            req = webob.Request.blank('/')
            args = {'action': 'index', 'controller': None}
            req.environ['wsgiorg.routing_args'] = [None, args]
            req.headers['Accept-Language'] = language
            resp = req.get_response(FakeApp())

            # Assert that the translated message appears in the response.

            exp_msg = xlated_msg_fmt % dict(target=target)
            self.assertThat(resp.json['error']['message'],
                            matchers.Equals(exp_msg))
            self.assertThat(xlation_mock.called, matchers.Equals(True))


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
        mock_sock_dup = mock_listen.return_value.dup.return_value

        server = environment.Server(mock.MagicMock(), host=self.host,
                                    port=self.port)
        server.start()
        self.assertTrue(mock_listen.called)
        self.assertFalse(mock_sock_dup.setsockopt.called)

    @mock.patch('eventlet.listen')
    @mock.patch('socket.getaddrinfo')
    def test_keepalive_set(self, mock_getaddrinfo, mock_listen):
        mock_getaddrinfo.return_value = [(1, 2, 3, 4, 5)]
        mock_sock_dup = mock_listen.return_value.dup.return_value

        server = environment.Server(mock.MagicMock(), host=self.host,
                                    port=self.port, keepalive=True)
        server.start()
        mock_sock_dup.setsockopt.assert_called_once_with(socket.SOL_SOCKET,
                                                         socket.SO_KEEPALIVE,
                                                         1)
        self.assertTrue(mock_listen.called)

    @mock.patch('eventlet.listen')
    @mock.patch('socket.getaddrinfo')
    def test_keepalive_and_keepidle_set(self, mock_getaddrinfo, mock_listen):
        mock_getaddrinfo.return_value = [(1, 2, 3, 4, 5)]
        mock_sock_dup = mock_listen.return_value.dup.return_value

        server = environment.Server(mock.MagicMock(), host=self.host,
                                    port=self.port, keepalive=True,
                                    keepidle=1)
        server.start()

        # keepidle isn't available in the OS X version of eventlet
        if hasattr(socket, 'TCP_KEEPIDLE'):
            self.assertEqual(mock_sock_dup.setsockopt.call_count, 2)

            # Test the last set of call args i.e. for the keepidle
            mock_sock_dup.setsockopt.assert_called_with(socket.IPPROTO_TCP,
                                                        socket.TCP_KEEPIDLE,
                                                        1)
        else:
            self.assertEqual(mock_sock_dup.setsockopt.call_count, 1)

        self.assertTrue(mock_listen.called)

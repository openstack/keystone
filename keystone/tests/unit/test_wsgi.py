# encoding: utf-8
#
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
import os
import uuid

import mock
import oslo_i18n
from oslo_serialization import jsonutils
import six
from six.moves import http_client
from testtools import matchers
import webob

from keystone.common import wsgi
from keystone import exception
from keystone.server.flask import core as server_flask
from keystone.tests import unit


class FakeApp(wsgi.Application):
    def index(self, request):
        return {'a': 'b'}


class FakeAttributeCheckerApp(wsgi.Application):
    def index(self, request):
        return request.params.mixed()

    def assert_attribute(self, body, attr):
        """Assert that the given request has a certain attribute."""
        ref = jsonutils.loads(body)
        self._require_attribute(ref, attr)

    def assert_attributes(self, body, attr):
        """Assert that the given request has a certain set attributes."""
        ref = jsonutils.loads(body)
        self._require_attributes(ref, attr)


class RouterTest(unit.TestCase):
    def setUp(self):
        self.router = wsgi.RoutersBase()
        super(RouterTest, self).setUp()

    def test_invalid_status(self):
        fake_mapper = uuid.uuid4().hex
        fake_controller = uuid.uuid4().hex
        fake_path = uuid.uuid4().hex
        fake_rel = uuid.uuid4().hex
        self.assertRaises(exception.Error,
                          self.router._add_resource,
                          fake_mapper, fake_controller, fake_path, fake_rel,
                          status=uuid.uuid4().hex)


class BaseWSGITest(unit.TestCase):
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
        self.assertEqual('application/json', resp.content_type)

    def test_query_string_available(self):
        class FakeApp(wsgi.Application):
            def index(self, request):
                return request.params.mixed()
        req = self._make_request(url='/?1=2')
        resp = req.get_response(FakeApp())
        self.assertEqual({'1': '2'}, jsonutils.loads(resp.body))

    def test_render_response(self):
        data = {'attribute': 'value'}
        body = b'{"attribute": "value"}'

        resp = wsgi.render_response(body=data)
        self.assertEqual('200 OK', resp.status)
        self.assertEqual(http_client.OK, resp.status_int)
        self.assertEqual(body, resp.body)
        self.assertEqual('X-Auth-Token', resp.headers.get('Vary'))
        self.assertEqual(str(len(body)), resp.headers.get('Content-Length'))

    def test_render_response_custom_status(self):
        resp = wsgi.render_response(
            status=(http_client.NOT_IMPLEMENTED,
                    http_client.responses[http_client.NOT_IMPLEMENTED]))
        self.assertEqual('501 Not Implemented', resp.status)
        self.assertEqual(http_client.NOT_IMPLEMENTED, resp.status_int)

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
        self.assertEqual('Some-Value', resp.headers.get('Custom-Header'))
        self.assertEqual('X-Auth-Token', resp.headers.get('Vary'))

    def test_render_response_non_str_headers_converted(self):
        resp = wsgi.render_response(
            headers=[('Byte-Header', 'Byte-Value'),
                     (u'Unicode-Header', u'Unicode-Value')])
        # assert that all headers are identified.
        self.assertEqual('Unicode-Value', resp.headers.get('Unicode-Header'))
        # assert that unicode value is converted, the expected type is str
        # on both python2 and python3.
        self.assertEqual(str,
                         type(resp.headers.get('Unicode-Header')))

    def test_render_response_no_body(self):
        resp = wsgi.render_response()
        self.assertEqual('204 No Content', resp.status)
        self.assertEqual(http_client.NO_CONTENT, resp.status_int)
        self.assertEqual(b'', resp.body)
        self.assertIsNone(resp.headers.get('Content-Type'))

    def test_render_response_head_with_body(self):
        resp = wsgi.render_response({'id': uuid.uuid4().hex}, method='HEAD')
        self.assertEqual(http_client.OK, resp.status_int)
        self.assertEqual(b'', resp.body)
        self.assertNotEqual('0', resp.headers.get('Content-Length'))
        self.assertEqual('application/json', resp.headers.get('Content-Type'))

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
        self.assertEqual(http_client.UNAUTHORIZED, resp.status_int)

    def test_render_exception_host(self):
        e = exception.Unauthorized(message=u'\u7f51\u7edc')
        req = self._make_request(url='/')
        context = {'host_url': 'http://%s:5000' % uuid.uuid4().hex,
                   'environment': req.environ}
        resp = wsgi.render_exception(e, context=context)

        self.assertEqual(http_client.UNAUTHORIZED, resp.status_int)

    def test_improperly_encoded_params(self):
        class FakeApp(wsgi.Application):
            def index(self, request):
                return request.params.mixed()
        # this is high bit set ASCII, copy & pasted from Windows.
        # aka code page 1252. It is not valid UTF8.
        req = self._make_request(url='/?name=nonexit%E8nt')
        self.assertRaises(exception.ValidationError, req.get_response,
                          FakeApp())

    def test_properly_encoded_params(self):
        class FakeApp(wsgi.Application):
            def index(self, request):
                return request.params.mixed()
        # nonexitènt encoded as UTF-8
        req = self._make_request(url='/?name=nonexit%C3%A8nt')
        resp = req.get_response(FakeApp())
        self.assertEqual({'name': u'nonexit\xe8nt'},
                         jsonutils.loads(resp.body))

    def test_base_url(self):
        class FakeApp(wsgi.Application):
            def index(self, request):
                return self.base_url(request.context_dict)
        req = self._make_request(url='/')
        # NOTE(gyee): according to wsgiref, if HTTP_HOST is present in the
        # request environment, it will be used to construct the base url.
        # SERVER_NAME and SERVER_PORT will be ignored. These are standard
        # WSGI environment variables populated by the webserver.
        req.environ.update({
            'SCRIPT_NAME': '/identity',
            'SERVER_NAME': '1.2.3.4',
            'wsgi.url_scheme': 'http',
            'SERVER_PORT': '80',
            'HTTP_HOST': '1.2.3.4',
        })
        resp = req.get_response(FakeApp())
        self.assertEqual(b"http://1.2.3.4/identity", resp.body)

        # if HTTP_HOST is absent, SERVER_NAME and SERVER_PORT will be used
        req = self._make_request(url='/')
        del req.environ['HTTP_HOST']
        req.environ.update({
            'SCRIPT_NAME': '/identity',
            'SERVER_NAME': '1.1.1.1',
            'wsgi.url_scheme': 'http',
            'SERVER_PORT': '1234',
        })
        resp = req.get_response(FakeApp())
        self.assertEqual(b"http://1.1.1.1:1234/identity", resp.body)

        # make sure keystone normalize the standard HTTP port 80 by stripping
        # it
        req = self._make_request(url='/')
        req.environ.update({'HTTP_HOST': 'foo:80',
                            'SCRIPT_NAME': '/identity'})
        resp = req.get_response(FakeApp())
        self.assertEqual(b"http://foo/identity", resp.body)

        # make sure keystone normalize the standard HTTPS port 443 by stripping
        # it
        req = self._make_request(url='/')
        req.environ.update({'HTTP_HOST': 'foo:443',
                            'SCRIPT_NAME': '/identity',
                            'wsgi.url_scheme': 'https'})
        resp = req.get_response(FakeApp())
        self.assertEqual(b"https://foo/identity", resp.body)

        # make sure non-standard port is preserved
        req = self._make_request(url='/')
        req.environ.update({'HTTP_HOST': 'foo:1234',
                            'SCRIPT_NAME': '/identity'})
        resp = req.get_response(FakeApp())
        self.assertEqual(b"http://foo:1234/identity", resp.body)

        # make sure version portion of the SCRIPT_NAME, '/v3' is stripped from
        # base url
        req = self._make_request(url='/')
        req.environ.update({'HTTP_HOST': 'foo:80',
                            'SCRIPT_NAME': '/identity/v3'})
        resp = req.get_response(FakeApp())
        self.assertEqual(b"http://foo/identity", resp.body)


class WSGIAppConfigTest(unit.TestCase):
    default_config_file = 'keystone.conf'
    custom_config_dir = '/etc/kst/'
    custom_config_files = ['kst.conf', 'kst2.conf']

    def test_config_files_have_default_values_when_envars_not_set(self):
        config_files = server_flask._get_config_files()
        config_files.sort()
        expected_config_files = []
        self.assertListEqual(config_files, expected_config_files)

    def test_config_files_have_default_values_with_empty_envars(self):
        env = {'OS_KEYSTONE_CONFIG_FILES': '',
               'OS_KEYSTONE_CONFIG_DIR': ''}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = []
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_single_config_file_under_default_config_dir(self):
        cfg = self.custom_config_files[0]
        env = {'OS_KEYSTONE_CONFIG_FILES': cfg}
        config_files = server_flask._get_config_files(env)
        expected_config_files = [cfg]
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_multiple_config_files_under_default_config_dir(self):
        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(self.custom_config_files)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = self.custom_config_files
        self.assertListEqual(config_files, expected_config_files)

        config_with_empty_strings = self.custom_config_files + ['', ' ']
        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(config_with_empty_strings)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_single_absolute_path_config_file(self):
        cfg = self.custom_config_files[0]
        cfgpath = os.path.join(self.custom_config_dir, cfg)
        env = {'OS_KEYSTONE_CONFIG_FILES': cfgpath}
        config_files = server_flask._get_config_files(env)
        self.assertListEqual(config_files, [cfgpath])

    def test_can_use_multiple_absolute_path_config_files(self):
        cfgpaths = [os.path.join(self.custom_config_dir, cfg)
                    for cfg in self.custom_config_files]
        cfgpaths.sort()
        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(cfgpaths)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, cfgpaths)

        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join(cfgpaths + ['', ' '])}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, cfgpaths)

    def test_can_use_default_config_files_with_custom_config_dir(self):
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [os.path.join(self.custom_config_dir,
                                              self.default_config_file)]
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_single_config_file_under_custom_config_dir(self):
        cfg = self.custom_config_files[0]
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': cfg}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [os.path.join(self.custom_config_dir, cfg)]
        self.assertListEqual(config_files, expected_config_files)

    def test_can_use_multiple_config_files_under_custom_config_dir(self):
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': ';'.join(self.custom_config_files)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [os.path.join(self.custom_config_dir, s)
                                 for s in self.custom_config_files]
        expected_config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

        config_with_empty_strings = self.custom_config_files + ['', ' ']
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': ';'.join(config_with_empty_strings)}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

    def test_can_mix_relative_and_absolute_paths_config_file(self):
        cfg0 = self.custom_config_files[0]
        cfgpath0 = os.path.join(self.custom_config_dir,
                                self.custom_config_files[0])
        cfgpath1 = os.path.join(self.custom_config_dir,
                                self.custom_config_files[1])
        env = {'OS_KEYSTONE_CONFIG_DIR': self.custom_config_dir,
               'OS_KEYSTONE_CONFIG_FILES': ';'.join([cfg0, cfgpath1])}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [cfgpath0, cfgpath1]
        expected_config_files.sort()
        self.assertListEqual(config_files, expected_config_files)

        env = {'OS_KEYSTONE_CONFIG_FILES': ';'.join([cfg0, cfgpath1])}
        config_files = server_flask._get_config_files(env)
        config_files.sort()
        expected_config_files = [cfg0, cfgpath1]
        expected_config_files.sort()
        self.assertListEqual(config_files, expected_config_files)


class ExtensionRouterTest(BaseWSGITest):
    def test_extensionrouter_local_config(self):
        class FakeRouter(wsgi.ExtensionRouter):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeRouter.factory({}, testkey="test")
        app = factory(self.app)
        self.assertIn("testkey", app.kwargs)
        self.assertEqual("test", app.kwargs["testkey"])

    def test_resource_not_found_message(self):
        class FakeRouter(wsgi.ExtensionRouter):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeRouter.factory({}, testkey="test")
        app = factory(self.app)
        req = webob.Request.blank('/WHATWHA')
        # Force the match in the Router to fail so we can verify
        # that the URL is included in the 404 error message.
        req.environ['wsgiorg.routing_args'] = [None, None]
        resp = app._dispatch(req)
        body = jsonutils.loads(resp.body)
        self.assertEqual(body['error']['message'],
                         u'(http://localhost/WHATWHA): The resource could '
                         'not be found.')


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
        self.assertEqual(exception.Unauthorized.code, resp.status_int)

    def test_middleware_type_error(self):
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise TypeError()

        req = self._make_request()
        req.environ['REMOTE_ADDR'] = '127.0.0.1'
        resp = FakeMiddleware(self.app)(req)
        # This is a validationerror type
        self.assertEqual(exception.ValidationError.code, resp.status_int)

    def test_middleware_exception_error(self):

        exception_str = b'EXCEPTIONERROR'

        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise exception.UnexpectedError(exception_str)

        def do_request():
            req = self._make_request()
            resp = FakeMiddleware(self.app)(req)
            self.assertEqual(exception.UnexpectedError.code, resp.status_int)
            return resp

        # Exception data should not be in the message when insecure_debug is
        # False
        self.config_fixture.config(debug=False, insecure_debug=False)
        self.assertNotIn(exception_str, do_request().body)

        # Exception data should be in the message when insecure_debug is True
        self.config_fixture.config(debug=True, insecure_debug=True)
        self.assertIn(exception_str, do_request().body)


class LocalizedResponseTest(unit.TestCase):
    def test_request_match_default(self):
        # The default language if no Accept-Language is provided is None
        req = webob.Request.blank('/')
        self.assertIsNone(wsgi.best_match_language(req))

    @mock.patch.object(oslo_i18n, 'get_available_languages')
    def test_request_match_language_expected(self, mock_gal):
        # If Accept-Language is a supported language, best_match_language()
        # returns it.

        language = 'bogus'
        mock_gal.return_value = [language]

        req = webob.Request.blank('/', headers={'Accept-Language': language})
        self.assertEqual(language, wsgi.best_match_language(req))

    @mock.patch.object(oslo_i18n, 'get_available_languages')
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
        self.assertNotEqual(six.text_type,
                            type(exception.Unauthorized.message_format))

    @mock.patch.object(oslo_i18n, 'get_available_languages')
    def test_get_localized_response(self, mock_gal):
        # If the request has the Accept-Language set to a supported language
        # and an exception is raised by the application that is translatable
        # then the response will have the translated message.

        language = 'bogus'
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
                def index(self, request):
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

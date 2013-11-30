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
from testtools import matchers


from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common.fixture import moxstubout
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
        self.assertEqual("test", app.kwargs["testkey"])

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
        class FakeMiddleware(wsgi.Middleware):
            def process_response(self, request, response):
                raise exception.UnexpectedError("EXCEPTIONERROR")

        req = self._make_request()
        resp = FakeMiddleware(self.app)(req)
        self.assertEqual(resp.status_int, exception.UnexpectedError.code)
        self.assertIn("EXCEPTIONERROR", resp.body)

    def test_middleware_local_config(self):
        class FakeMiddleware(wsgi.Middleware):
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

        factory = FakeMiddleware.factory({}, testkey="test")
        app = factory(self.app)
        self.assertIn("testkey", app.kwargs)
        self.assertEqual("test", app.kwargs["testkey"])


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

        fixture = self.useFixture(moxstubout.MoxStubout())
        self.stubs = fixture.stubs

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
        self.assertEqual(req.best_match_language(), 'it')

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


class TestControllerMethodInspection(tests.TestCase):

    def setUp(self):
        super(TestControllerMethodInspection, self).setUp()
        self.app = wsgi.Application()
        self.inspect = self.app._method_inspect

    def assertSuccess(self, func_user_test, params):
        self.inspect(func_user_test, params)

    def assertFailure(self, func_user_test, params,
                      expected_extra=None, expected_missing=None):
        # NOTE(dstanek): In Python2.7+ assertRaises can be used as a context
        # manager. This would make the code much cleaner.
        try:
            self.inspect(func_user_test, params)
        except exception.ControllerArgsError as e:
            message = str(e)

            for param in expected_extra or []:
                expected_msg = '%s is not allowed.' % param
                self.assertThat(message, matchers.Contains(expected_msg))

            for param in expected_missing or []:
                expected_msg = '%s is required.' % param
                self.assertThat(message, matchers.Contains(expected_msg))

        else:
            raise self.failureException('ControllerArgsError not raised')

    def test_all_required_parameters_provided(self):

        def func_under_test(a):
            pass
        self.assertSuccess(func_under_test, params=['a'])

        def func_under_test(a, b):
            pass
        self.assertSuccess(func_under_test, params=['a', 'b'])

    def test_optional_parameters_provided(self):

        def func_under_test(a=None):
            pass
        self.assertSuccess(func_under_test, params=['a'])

    def test_optional_parameters_not_provided(self):

        def func_under_test(a=None):
            pass
        self.assertSuccess(func_under_test, params=[])

        def func_under_test(a, b=None):
            pass
        self.assertSuccess(func_under_test, params=['a'])

    def test_some_required_parameters_missing(self):

        def func_under_test(a, b):
            pass
        self.assertFailure(func_under_test, params=['b'],
                           expected_missing=['a'])

    def test_extra_parameter_supplied(self):

        def func_under_test(a):
            pass
        self.assertFailure(func_under_test, params=['a', 'b'],
                           expected_extra=['b'])

    def test_extra_parameter_supplied_with_kwargs_defined(self):

        def func_under_test(a, **kw):
            pass
        self.assertSuccess(func_under_test, params=['a', 'b'])

    def test_some_required_parameters_missing_with_kwargs_defined(self):

        def func_under_test(a, b, **kw):
            pass
        self.assertFailure(func_under_test, params=['a'],
                           expected_missing=['b'])

    def test_a_method_works(self):

        class AppUnderTest(object):
            def index(self, a):
                pass
        self.assertSuccess(AppUnderTest().index, params=['a'])

        class AppUnderTest(object):
            def index(self, a, b):
                pass
        self.assertFailure(AppUnderTest().index, params=['a'],
                           expected_missing=['b'])

    def test_auto_provided_params_are_ignored(self):

        class AppUnderTest(object):
            def index(self, context):
                pass
        self.assertSuccess(AppUnderTest().index, params=[])

        class AppUnderTest(object):
            def index(self, context, a):
                pass
        self.assertSuccess(AppUnderTest().index, params=['a'])


class TestWSGIControllerMethodInspection(BaseWSGITest):

    class FakeAppWithArgs(wsgi.Application):
        def index(self, context, arg0, arg1):
            return arg0, arg1

    def _execute_test(self, app, expected_body, params=None):
        req = self._make_request()
        if params:
            req.environ['openstack.params'] = params
        resp = req.get_response(app())
        self.assertEqual(jsonutils.loads(resp.body), expected_body)

    def test_controller_method_with_no_args(self):
        class FakeApp(wsgi.Application):
            def index(self, context):
                return ['index']

        self._execute_test(FakeApp, ['index'])

    def test_controller_method_with_correct_args(self):
        self._execute_test(self.FakeAppWithArgs, ['value0', 'value1'],
                           {'arg0': 'value0', 'arg1': 'value1'})

    def test_controller_method_with_missing_arg(self):
        expected_body = {
            "error": {
                "message": "arg1 is required.",
                "code": 400,
                "title": "Bad Request"
            }
        }
        self._execute_test(self.FakeAppWithArgs, expected_body,
                           {'arg0': 'value0'})

    def test_controller_method_with_multiple_errors(self):
        expected_body = {
            "error": {
                "message": "arg3 is not allowed. "
                           "arg0 is required. "
                           "arg1 is required.",
                "code": 400,
                "title": "Bad Request"
            }
        }
        self._execute_test(self.FakeAppWithArgs, expected_body,
                           {'arg3': 'value3'})

    def test_controller_method_with_default_args(self):
        class FakeApp(wsgi.Application):
            def index(self, context, arg0, arg1='1'):
                return arg0, arg1

        self._execute_test(FakeApp, ['0', '1'], {'arg0': '0'})

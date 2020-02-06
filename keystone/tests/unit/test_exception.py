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

# NOTE(morgan): These test cases are used for AuthContextMiddleware exception
# rendering.

import uuid

import fixtures
from oslo_config import fixture as config_fixture
from oslo_log import log
from oslo_serialization import jsonutils

import keystone.conf
from keystone import exception
from keystone.server.flask.request_processing.middleware import auth_context
from keystone.tests import unit


CONF = keystone.conf.CONF


class ExceptionTestCase(unit.BaseTestCase):
    def assertValidJsonRendering(self, e):
        resp = auth_context.render_exception(e)
        self.assertEqual(e.code, resp.status_int)
        self.assertEqual('%s %s' % (e.code, e.title), resp.status)

        j = jsonutils.loads(resp.body)
        self.assertIsNotNone(j.get('error'))
        self.assertIsNotNone(j['error'].get('code'))
        self.assertIsNotNone(j['error'].get('title'))
        self.assertIsNotNone(j['error'].get('message'))
        self.assertNotIn('\n', j['error']['message'])
        self.assertNotIn('  ', j['error']['message'])
        self.assertIs(type(j['error']['code']), int)

    def test_all_json_renderings(self):
        """Everything callable in the exception module should be renderable.

        ... except for the base error class (exception.Error), which is not
        user-facing.

        This test provides a custom message to bypass docstring parsing, which
        should be tested separately.

        """
        for cls in [x for x in exception.__dict__.values() if callable(x)]:
            if cls is not exception.Error and isinstance(cls, exception.Error):
                self.assertValidJsonRendering(cls(message='Overridden.'))

    def test_validation_error(self):
        target = uuid.uuid4().hex
        attribute = uuid.uuid4().hex
        e = exception.ValidationError(target=target, attribute=attribute)
        self.assertValidJsonRendering(e)
        self.assertIn(target, str(e))
        self.assertIn(attribute, str(e))

    def test_not_found(self):
        target = uuid.uuid4().hex
        e = exception.NotFound(target=target)
        self.assertValidJsonRendering(e)
        self.assertIn(target, str(e))

    def test_forbidden_title(self):
        e = exception.Forbidden()
        resp = auth_context.render_exception(e)
        j = jsonutils.loads(resp.body)
        self.assertEqual('Forbidden', e.title)
        self.assertEqual('Forbidden', j['error'].get('title'))

    def test_unicode_message(self):
        message = u'Comment \xe7a va'
        e = exception.Error(message)

        try:
            self.assertEqual(message, str(e))
        except UnicodeEncodeError:
            self.fail("unicode error message not supported")

    def test_unicode_string(self):
        e = exception.ValidationError(attribute='xx',
                                      target='Long \xe2\x80\x93 Dash')
        self.assertIn('Long \xe2\x80\x93 Dash', str(e))

    def test_invalid_unicode_string(self):
        # NOTE(jamielennox): This is a complete failure case so what is
        # returned in the exception message is not that important so long
        # as there is an error with a message
        e = exception.ValidationError(attribute='xx',
                                      target='\xe7a va')
        self.assertIn('\xe7a va', str(e))


class UnexpectedExceptionTestCase(ExceptionTestCase):
    """Test if internal info is exposed to the API user on UnexpectedError."""

    class SubClassExc(exception.UnexpectedError):
        debug_message_format = 'Debug Message: %(debug_info)s'

    def setUp(self):
        super(UnexpectedExceptionTestCase, self).setUp()
        self.exc_str = uuid.uuid4().hex
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))

    def test_unexpected_error_no_debug(self):
        self.config_fixture.config(debug=False)
        e = exception.UnexpectedError(exception=self.exc_str)
        self.assertNotIn(self.exc_str, str(e))

    def test_unexpected_error_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)
        e = exception.UnexpectedError(exception=self.exc_str)
        self.assertIn(self.exc_str, str(e))

    def test_unexpected_error_subclass_no_debug(self):
        self.config_fixture.config(debug=False)
        e = UnexpectedExceptionTestCase.SubClassExc(
            debug_info=self.exc_str)
        self.assertEqual(exception.UnexpectedError.message_format,
                         str(e))

    def test_unexpected_error_subclass_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)
        subclass = self.SubClassExc

        e = subclass(debug_info=self.exc_str)
        expected = subclass.debug_message_format % {'debug_info': self.exc_str}
        self.assertEqual(
            '%s %s' % (expected, exception.SecurityError.amendment),
            str(e))

    def test_unexpected_error_custom_message_no_debug(self):
        self.config_fixture.config(debug=False)
        e = exception.UnexpectedError(self.exc_str)
        self.assertEqual(exception.UnexpectedError.message_format,
                         str(e))

    def test_unexpected_error_custom_message_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)
        e = exception.UnexpectedError(self.exc_str)
        self.assertEqual(
            '%s %s' % (self.exc_str, exception.SecurityError.amendment),
            str(e))

    def test_unexpected_error_custom_message_exception_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)
        orig_e = exception.NotFound(target=uuid.uuid4().hex)
        e = exception.UnexpectedError(orig_e)
        self.assertEqual(
            '%s %s' % (str(orig_e),
                       exception.SecurityError.amendment),
            str(e))

    def test_unexpected_error_custom_message_binary_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)
        binary_msg = b'something'
        e = exception.UnexpectedError(binary_msg)
        self.assertEqual(
            '%s %s' % (str(binary_msg),
                       exception.SecurityError.amendment),
            str(e))


class SecurityErrorTestCase(ExceptionTestCase):
    """Test whether security-related info is exposed to the API user."""

    def setUp(self):
        super(SecurityErrorTestCase, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))

    def test_unauthorized_exposure(self):
        self.config_fixture.config(debug=False)

        risky_info = uuid.uuid4().hex
        e = exception.Unauthorized(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, str(e))

    def test_unauthorized_exposure_in_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)

        risky_info = uuid.uuid4().hex
        e = exception.Unauthorized(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, str(e))

    def test_forbidden_exposure(self):
        self.config_fixture.config(debug=False)

        risky_info = uuid.uuid4().hex
        e = exception.Forbidden(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, str(e))

    def test_forbidden_exposure_in_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)

        risky_info = uuid.uuid4().hex
        e = exception.Forbidden(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, str(e))

    def test_forbidden_action_exposure(self):
        self.config_fixture.config(debug=False)

        risky_info = uuid.uuid4().hex
        action = uuid.uuid4().hex
        e = exception.ForbiddenAction(message=risky_info, action=action)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, str(e))
        self.assertIn(action, str(e))
        self.assertNotIn(exception.SecurityError.amendment, str(e))

        e = exception.ForbiddenAction(action=action)
        self.assertValidJsonRendering(e)
        self.assertIn(action, str(e))
        self.assertNotIn(exception.SecurityError.amendment, str(e))

    def test_forbidden_action_exposure_in_debug(self):
        self.config_fixture.config(debug=True, insecure_debug=True)

        risky_info = uuid.uuid4().hex
        action = uuid.uuid4().hex

        e = exception.ForbiddenAction(message=risky_info, action=action)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, str(e))
        self.assertIn(exception.SecurityError.amendment, str(e))

        e = exception.ForbiddenAction(action=action)
        self.assertValidJsonRendering(e)
        self.assertIn(action, str(e))
        self.assertNotIn(exception.SecurityError.amendment, str(e))

    def test_forbidden_action_no_message(self):
        # When no custom message is given when the ForbiddenAction (or other
        # SecurityError subclass) is created the exposed message is the same
        # whether debug is enabled or not.

        action = uuid.uuid4().hex

        self.config_fixture.config(debug=False)
        e = exception.ForbiddenAction(action=action)
        exposed_message = str(e)
        self.assertIn(action, exposed_message)
        self.assertNotIn(exception.SecurityError.amendment, str(e))

        self.config_fixture.config(debug=True)
        e = exception.ForbiddenAction(action=action)
        self.assertEqual(exposed_message, str(e))

    def test_unicode_argument_message(self):
        self.config_fixture.config(debug=False)

        risky_info = u'\u7ee7\u7eed\u884c\u7f29\u8fdb\u6216'
        e = exception.Forbidden(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, str(e))


class TestSecurityErrorTranslation(unit.BaseTestCase):
    """Test i18n for SecurityError exceptions."""

    def setUp(self):
        super(TestSecurityErrorTranslation, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        self.config_fixture.config(insecure_debug=False)
        self.warning_log = self.useFixture(fixtures.FakeLogger(level=log.WARN))

        exception._FATAL_EXCEPTION_FORMAT_ERRORS = False
        self.addCleanup(
            setattr, exception, '_FATAL_EXCEPTION_FORMAT_ERRORS', True)

    class CustomSecurityError(exception.SecurityError):
        message_format = 'We had a failure in the %(place)r'

    class CustomError(exception.Error):
        message_format = 'We had a failure in the %(place)r'

    def test_nested_translation_of_SecurityErrors(self):
        e = self.CustomSecurityError(place='code')
        ('Admiral found this in the log: %s') % e
        self.assertNotIn('programmer error', self.warning_log.output)

    def test_that_regular_Errors_can_be_deep_copied(self):
        e = self.CustomError(place='code')
        ('Admiral found this in the log: %s') % e
        self.assertNotIn('programmer error', self.warning_log.output)

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

from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone import tests


CONF = config.CONF


class ExceptionTestCase(tests.TestCase):
    def assertValidJsonRendering(self, e):
        resp = wsgi.render_exception(e)
        self.assertEqual(resp.status_int, e.code)
        self.assertEqual(resp.status, '%s %s' % (e.code, e.title))

        j = jsonutils.loads(resp.body)
        self.assertIsNotNone(j.get('error'))
        self.assertIsNotNone(j['error'].get('code'))
        self.assertIsNotNone(j['error'].get('title'))
        self.assertIsNotNone(j['error'].get('message'))
        self.assertNotIn('\n', j['error']['message'])
        self.assertNotIn('  ', j['error']['message'])
        self.assertTrue(type(j['error']['code']) is int)

    def test_all_json_renderings(self):
        """Everything callable in the exception module should be renderable.

        ... except for the base error class (exception.Error), which is not
        user-facing.

        This test provides a custom message to bypass docstring parsing, which
        should be tested separately.

        """
        for cls in [x for x in exception.__dict__.values() if callable(x)]:
            if cls is not exception.Error and isinstance(cls, exception.Error):
                self.assertValidJsonRendering(cls(message='Overriden.'))

    def test_validation_error(self):
        target = uuid.uuid4().hex
        attribute = uuid.uuid4().hex
        e = exception.ValidationError(target=target, attribute=attribute)
        self.assertValidJsonRendering(e)
        self.assertIn(target, unicode(e))
        self.assertIn(attribute, unicode(e))

    def test_not_found(self):
        target = uuid.uuid4().hex
        e = exception.NotFound(target=target)
        self.assertValidJsonRendering(e)
        self.assertIn(target, unicode(e))

    def test_403_title(self):
        e = exception.Forbidden()
        resp = wsgi.render_exception(e)
        j = jsonutils.loads(resp.body)
        self.assertEqual('Forbidden', e.title)
        self.assertEqual('Forbidden', j['error'].get('title'))

    def test_unicode_message(self):
        message = u'Comment \xe7a va'
        e = exception.Error(message)

        try:
            self.assertEqual(unicode(e), message)
        except UnicodeEncodeError:
            self.fail("unicode error message not supported")


class SecurityErrorTestCase(ExceptionTestCase):
    """Tests whether security-related info is exposed to the API user."""
    def test_unauthorized_exposure(self):
        self.opt(debug=False)

        risky_info = uuid.uuid4().hex
        e = exception.Unauthorized(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, unicode(e))

    def test_unauthorized_exposure_in_debug(self):
        self.opt(debug=True)

        risky_info = uuid.uuid4().hex
        e = exception.Unauthorized(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, unicode(e))

    def test_forbidden_exposure(self):
        self.opt(debug=False)

        risky_info = uuid.uuid4().hex
        e = exception.Forbidden(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, unicode(e))

    def test_forbidden_exposure_in_debug(self):
        self.opt(debug=True)

        risky_info = uuid.uuid4().hex
        e = exception.Forbidden(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, unicode(e))

    def test_forbidden_action_exposure(self):
        self.opt(debug=False)

        risky_info = uuid.uuid4().hex
        action = uuid.uuid4().hex
        e = exception.ForbiddenAction(message=risky_info, action=action)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, unicode(e))
        self.assertIn(action, unicode(e))

        e = exception.ForbiddenAction(action=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, unicode(e))

    def test_forbidden_action_exposure_in_debug(self):
        self.opt(debug=True)

        risky_info = uuid.uuid4().hex

        e = exception.ForbiddenAction(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, unicode(e))

        e = exception.ForbiddenAction(action=risky_info)
        self.assertValidJsonRendering(e)
        self.assertIn(risky_info, unicode(e))

    def test_unicode_argument_message(self):
        self.opt(debug=False)

        risky_info = u'\u7ee7\u7eed\u884c\u7f29\u8fdb\u6216'
        e = exception.Forbidden(message=risky_info)
        self.assertValidJsonRendering(e)
        self.assertNotIn(risky_info, unicode(e))

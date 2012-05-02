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
import uuid
import json

from keystone.common import wsgi
from keystone import exception
from keystone import test


class ExceptionTestCase(test.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def assertValidJsonRendering(self, e):
        resp = wsgi.render_exception(e)
        self.assertEqual(resp.status_int, e.code)
        self.assertEqual(resp.status, '%s %s' % (e.code, e.title))

        j = json.loads(resp.body)
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
        should be tested seperately.

        """
        for cls in [x for x in exception.__dict__.values() if callable(x)]:
            if cls is not exception.Error:
                self.assertValidJsonRendering(cls(message='Overriden.'))

    def test_validation_error(self):
        target = uuid.uuid4().hex
        attribute = uuid.uuid4().hex
        e = exception.ValidationError(target=target, attribute=attribute)
        self.assertValidJsonRendering(e)
        self.assertIn(target, str(e))
        self.assertIn(attribute, str(e))

    def test_forbidden_action(self):
        action = uuid.uuid4().hex
        e = exception.ForbiddenAction(action=action)
        self.assertValidJsonRendering(e)
        self.assertIn(action, str(e))

    def test_not_found(self):
        target = uuid.uuid4().hex
        e = exception.NotFound(target=target)
        self.assertValidJsonRendering(e)
        self.assertIn(target, str(e))

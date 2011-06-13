# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Decorators useful in unit tests"""

import functools


def content_type(func, content_type='json'):
    """
    Decorator for a test case method that sets the test case's
    content_type to 'json' or 'xml' and resets it afterwards to
    the original setting. This also asserts that if there is a
    value for the test object's `res` attribute, that the content-type
    header of the response is correct.
    """
    @functools.wraps(func)
    def wrapped(*a, **kwargs):
        test_obj = a[0]
        orig_content_type = test_obj.content_type
        try:
            test_obj.content_type = content_type
            func(*a, **kwargs)
            if getattr(test_obj, 'res'):
                expected = 'application/%s' % content_type
                got = test_obj.res.headers['content-type'].split(';')[0]
                test_obj.assertEqual(expected, got,
                                     "Bad content type: %s. Expected: %s" %
                                     (got, expected))
        finally:
            test_obj.content_type = orig_content_type
    return wrapped


jsonify = functools.partial(content_type, content_type='json')
xmlify = functools.partial(content_type, content_type='xml')

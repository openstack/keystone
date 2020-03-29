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

"""Useful utilities for tests."""

import functools
import os
import time
import uuid

from testtools import testcase


TZ = None


def timezone(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tz_original = os.environ.get('TZ')
        try:
            if TZ:
                os.environ['TZ'] = TZ
                time.tzset()
            return func(*args, **kwargs)
        finally:
            if TZ:
                if tz_original:
                    os.environ['TZ'] = tz_original
                else:
                    if 'TZ' in os.environ:
                        del os.environ['TZ']
                time.tzset()
    return wrapper


def new_uuid():
    """Return a string UUID."""
    return uuid.uuid4().hex


def wip(message, expected_exception=Exception, bug=None):
    """Mark a test as work in progress.

    Based on code by Nat Pryce:
    https://gist.github.com/npryce/997195#file-wip-py

    The test will always be run. If the test fails then a TestSkipped
    exception is raised. If the test passes an AssertionError exception
    is raised so that the developer knows they made the test pass. This
    is a reminder to remove the decorator.

    :param message: a string message to help clarify why the test is
                    marked as a work in progress
    :param expected_exception: an exception class that will be checked for
                               when @wip verifies an exception is raised. The
                               test will fail if a different exception is
                               raised. Default is "any" exception is valid
    :param bug: (optional) a string for tracking the bug and what bug should
                cause the @wip decorator to be removed from the testcase

    Usage:
      >>> @wip('Expected Error', expected_exception=Exception, bug="#000000")
      >>> def test():
      >>>     pass

    """
    if bug:
        bugstr = " (BugID " + bug + ")"
    else:
        bugstr = ""

    def _wip(f):
        @functools.wraps(f)
        def run_test(*args, **kwargs):
            __e = None
            try:
                f(*args, **kwargs)
            except Exception as __e:  # noqa F841
                if (expected_exception != Exception and
                        not isinstance(__e, expected_exception)):
                    raise AssertionError(
                        'Work In Progress Test Failed%(bugstr)s with '
                        'unexpected exception. Expected "%(expected)s" '
                        'got "%(exception)s": %(message)s ' %
                        {'message': message, 'bugstr': bugstr,
                         'expected': expected_exception.__class__.__name__,
                         'exception': __e.__class__.__name__})
                # NOTE(notmorgan): We got the expected exception we can safely
                # skip this test.
                raise testcase.TestSkipped(
                    'Work In Progress Test Failed as '
                    'expected%(bugstr)s: %(message)s' %
                    {'message': message, 'bugstr': bugstr})

            raise AssertionError('Work In Progress Test Passed%(bugstr)s: '
                                 '%(message)s' % {'message': message,
                                                  'bugstr': bugstr})

        return run_test

    return _wip

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

from oslo_log import log
import six
from testtools import testcase


LOG = log.getLogger(__name__)

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


def wip(message):
    """Mark a test as work in progress.

    Based on code by Nat Pryce:
    https://gist.github.com/npryce/997195#file-wip-py

    The test will always be run. If the test fails then a TestSkipped
    exception is raised. If the test passes an AssertionError exception
    is raised so that the developer knows they made the test pass. This
    is a reminder to remove the decorator.

    :param message: a string message to help clarify why the test is
                    marked as a work in progress

    usage:
      >>> @wip('waiting on bug #000000')
      >>> def test():
      >>>     pass

    """

    def _wip(f):
        @six.wraps(f)
        def run_test(*args, **kwargs):
            try:
                f(*args, **kwargs)
            except Exception:
                raise testcase.TestSkipped('work in progress test failed: ' +
                                           message)

            raise AssertionError('work in progress test passed: ' + message)

        return run_test

    return _wip

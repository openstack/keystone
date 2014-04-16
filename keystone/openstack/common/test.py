# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
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

##############################################################################
##############################################################################
##
## DO NOT MODIFY THIS FILE
##
## This file is being graduated to the keystonetest library. Please make all
## changes there, and only backport critical fixes here. - dhellmann
##
##############################################################################
##############################################################################

"""Common utilities used in testing"""

import logging
import os
import tempfile

import fixtures
import testtools

_TRUE_VALUES = ('True', 'true', '1', 'yes')
_LOG_FORMAT = "%(levelname)8s [%(name)s] %(message)s"


class BaseTestCase(testtools.TestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self._set_timeout()
        self._fake_output()
        self._fake_logs()
        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())
        self.tempdirs = []

    def _set_timeout(self):
        test_timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            test_timeout = int(test_timeout)
        except ValueError:
            # If timeout value is invalid do not set a timeout.
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))

    def _fake_output(self):
        if os.environ.get('OS_STDOUT_CAPTURE') in _TRUE_VALUES:
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if os.environ.get('OS_STDERR_CAPTURE') in _TRUE_VALUES:
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))

    def _fake_logs(self):
        if os.environ.get('OS_DEBUG') in _TRUE_VALUES:
            level = logging.DEBUG
        else:
            level = logging.INFO
        capture_logs = os.environ.get('OS_LOG_CAPTURE') in _TRUE_VALUES
        if capture_logs:
            self.useFixture(
                fixtures.FakeLogger(
                    format=_LOG_FORMAT,
                    level=level,
                    nuke_handlers=capture_logs,
                )
            )
        else:
            logging.basicConfig(format=_LOG_FORMAT, level=level)

    def create_tempfiles(self, files, ext='.conf'):
        tempfiles = []
        for (basename, contents) in files:
            if not os.path.isabs(basename):
                (fd, path) = tempfile.mkstemp(prefix=basename, suffix=ext)
            else:
                path = basename + ext
                fd = os.open(path, os.O_CREAT | os.O_WRONLY)
            tempfiles.append(path)
            try:
                os.write(fd, contents)
            finally:
                os.close(fd)
        return tempfiles

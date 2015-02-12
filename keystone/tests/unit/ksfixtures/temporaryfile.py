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

import os
import tempfile

import fixtures


class SecureTempFile(fixtures.Fixture):
    """A fixture for creating a secure temp file."""

    def setUp(self):
        super(SecureTempFile, self).setUp()

        _fd, self.file_name = tempfile.mkstemp()
        # Make sure no file descriptors are leaked, close the unused FD.
        os.close(_fd)
        self.addCleanup(os.remove, self.file_name)

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import re
import sys

from keystone.common import utils


RE_VERSION = re.compile(r'^OpenSSL 1\.\d\.\d')


def setup_package():
    check_dependencies()


def check_dependencies():
    check_openssl_version()


def check_openssl_version():
    openssl_version = utils.check_output(['openssl', 'version'])
    openssl_version = openssl_version.strip()
    match = RE_VERSION.match(openssl_version)
    if not match:
        raise AssertionError('Incorrect version of OpenSSL (%s),'
                             ' 1.0.0+ required.' % openssl_version)

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

from oslo_log import versionutils


versionutils.deprecated(
    what='keystone.common.ldap',
    as_of=versionutils.deprecated.NEWTON,
    remove_in=+2,
    in_favor_of='keystone.identity.backends.ldap.common')

# NOTE(notmorgan): This is maintained for compatibility in case outside
# developers are relying on this location.
from keystone.identity.backends.ldap.common import *  # noqa

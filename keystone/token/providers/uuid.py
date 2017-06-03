# Copyright 2013 OpenStack Foundation
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

"""Keystone UUID Token Provider."""

from __future__ import absolute_import

from oslo_log import versionutils

import uuid

from keystone.token.providers import common


class Provider(common.BaseProvider):

    @versionutils.deprecated(
        as_of=versionutils.deprecated.PIKE,
        what='UUID Token Provider "[token] provider=uuid"',
        in_favor_of='Fernet token Provider "[token] provider=fernet"',
        remove_in=+2)
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)

    def _get_token_id(self, token_data):
        return uuid.uuid4().hex

    @property
    def _supports_bind_authentication(self):
        """Return if the token provider supports bind authentication methods.

        :returns: True
        """
        return True

    def needs_persistence(self, token=None):
        """Should the token be written to a backend."""
        return True

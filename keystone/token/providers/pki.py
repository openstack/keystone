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

"""Keystone PKI Token Provider"""

import json

from keystoneclient.common import cms

from keystone.common import environment
from keystone import config
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log
from keystone.token.providers import common


CONF = config.CONF

LOG = log.getLogger(__name__)


class Provider(common.BaseProvider):
    def _get_token_id(self, token_data):
        try:
            # force conversion to a string as the keystone client cms code
            # produces unicode.  This can be removed if the client returns
            # str()
            # TODO(ayoung): Make to a byte_str for Python3
            token_id = str(cms.cms_sign_token(json.dumps(token_data),
                                              CONF.signing.certfile,
                                              CONF.signing.keyfile))
            return token_id
        except environment.subprocess.CalledProcessError:
            LOG.exception(_('Unable to sign token'))
            raise exception.UnexpectedError(_(
                'Unable to sign token.'))

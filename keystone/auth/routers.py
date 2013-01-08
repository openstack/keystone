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

from keystone.auth import controllers
from keystone.common import router


def append_v3_routers(mapper, routers):
    auth_controller = controllers.Auth()

    mapper.connect('/auth/tokens',
                   controller=auth_controller,
                   action='authenticate_for_token',
                   conditions=dict(method=['POST']))
    mapper.connect('/auth/tokens',
                   controller=auth_controller,
                   action='check_token',
                   conditions=dict(method=['HEAD']))
    mapper.connect('/auth/tokens',
                   controller=auth_controller,
                   action='revoke_token',
                   conditions=dict(method=['DELETE']))
    mapper.connect('/auth/tokens',
                   controller=auth_controller,
                   action='validate_token',
                   conditions=dict(method=['GET']))
    mapper.connect('/auth/tokens/OS-PKI/revoked',
                   controller=auth_controller,
                   action='revocation_list',
                   conditions=dict(method=['GET']))

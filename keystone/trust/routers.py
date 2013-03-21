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
"""WSGI Routers for the Identity service."""

from keystone.trust import controllers
from keystone.common import router


def append_v3_routers(mapper, routers):
    trust_controller = controllers.TrustV3()

    mapper.connect('/RH-TRUST/trusts',
                   controller=trust_controller,
                   action='create_trust',
                   conditions=dict(method=['POST']))

    mapper.connect('/RH-TRUST/trusts',
                   controller=trust_controller,
                   action='list_trusts',
                   conditions=dict(method=['GET']))

    mapper.connect('/RH-TRUST/trusts/{trust_id}',
                   controller=trust_controller,
                   action='delete_trust',
                   conditions=dict(method=['DELETE']))

    mapper.connect('/RH-TRUST/trusts/{trust_id}',
                   controller=trust_controller,
                   action='get_trust',
                   conditions=dict(method=['GET']))

    mapper.connect('/RH-TRUST/trusts/{trust_id}/roles',
                   controller=trust_controller,
                   action='list_roles_for_trust',
                   conditions=dict(method=['GET']))

    mapper.connect('/RH-TRUST/trusts/{trust_id}/roles/{role_id}',
                   controller=trust_controller,
                   action='check_role_for_trust',
                   conditions=dict(method=['HEAD']))

    mapper.connect('/RH-TRUST/trusts/{trust_id}/roles/{role_id}',
                   controller=trust_controller,
                   action='get_role_for_trust',
                   conditions=dict(method=['GET']))

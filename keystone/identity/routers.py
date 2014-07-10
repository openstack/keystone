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
"""WSGI Routers for the Identity service."""
from keystone.common import router
from keystone.common import wsgi
from keystone.identity import controllers


class Admin(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # User Operations
        user_controller = controllers.User()
        mapper.connect('/users/{user_id}',
                       controller=user_controller,
                       action='get_user',
                       conditions=dict(method=['GET']))


def append_v3_routers(mapper, routers):
    user_controller = controllers.UserV3()
    routers.append(
        router.Router(user_controller,
                      'users', 'user'))
    mapper.connect('/users/{user_id}/password',
                   controller=user_controller,
                   action='change_password',
                   conditions=dict(method=['POST']))

    mapper.connect('/groups/{group_id}/users',
                   controller=user_controller,
                   action='list_users_in_group',
                   conditions=dict(method=['GET']))

    mapper.connect('/groups/{group_id}/users/{user_id}',
                   controller=user_controller,
                   action='add_user_to_group',
                   conditions=dict(method=['PUT']))

    mapper.connect('/groups/{group_id}/users/{user_id}',
                   controller=user_controller,
                   action='check_user_in_group',
                   conditions=dict(method=['GET', 'HEAD']))

    mapper.connect('/groups/{group_id}/users/{user_id}',
                   controller=user_controller,
                   action='remove_user_from_group',
                   conditions=dict(method=['DELETE']))

    group_controller = controllers.GroupV3()
    routers.append(
        router.Router(group_controller,
                      'groups', 'group'))
    mapper.connect('/users/{user_id}/groups',
                   controller=group_controller,
                   action='list_groups_for_user',
                   conditions=dict(method=['GET']))

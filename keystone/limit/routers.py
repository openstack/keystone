# Copyright 2018 Huawei
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

from keystone.common import json_home
from keystone.common import wsgi
from keystone.limit import controllers


class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):

        self._add_resource(
            mapper, controllers.RegisteredLimitV3(),
            path='/registered_limits',
            post_action='create_registered_limits',
            put_action='update_registered_limits',
            get_head_action='list_registered_limits',
            status=json_home.Status.EXPERIMENTAL,
            rel=json_home.build_v3_resource_relation('registered_limits')
        )

        self._add_resource(
            mapper, controllers.RegisteredLimitV3(),
            path='/registered_limits/{registered_limit_id}',
            get_head_action='get_registered_limit',
            delete_action='delete_registered_limit',
            status=json_home.Status.EXPERIMENTAL,
            rel=json_home.build_v3_resource_relation('registered_limits'),
            path_vars={
                'registered_limit_id':
                    json_home.Parameters.REGISTERED_LIMIT_ID}
        )

        self._add_resource(
            mapper, controllers.LimitV3(),
            path='/limits',
            post_action='create_limits',
            put_action='update_limits',
            get_head_action='list_limits',
            status=json_home.Status.EXPERIMENTAL,
            rel=json_home.build_v3_resource_relation('limits')
        )

        self._add_resource(
            mapper, controllers.LimitV3(),
            path='/limits/{limit_id}',
            get_head_action='get_limit',
            delete_action='delete_limit',
            status=json_home.Status.EXPERIMENTAL,
            rel=json_home.build_v3_resource_relation('limits'),
            path_vars={
                'limit_id':
                    json_home.Parameters.LIMIT_ID}
        )

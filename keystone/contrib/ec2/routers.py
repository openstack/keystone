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

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib.ec2 import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-EC2',
    extension_version='1.0')


class Routers(wsgi.RoutersBase):

    _path_prefixes = ('ec2tokens',)

    def append_v3_routers(self, mapper, routers):
        ec2_controller = controllers.Ec2ControllerV3()
        # validation
        self._add_resource(
            mapper, ec2_controller,
            path='/ec2tokens',
            post_action='authenticate',
            rel=build_resource_relation(resource_name='ec2tokens'))

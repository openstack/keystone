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
from keystone.contrib.example import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-EXAMPLE', extension_version='1.0')


class ExampleRouter(wsgi.V3ExtensionRouter):

    PATH_PREFIX = '/OS-EXAMPLE'

    def add_routes(self, mapper):
        example_controller = controllers.ExampleV3Controller()

        self._add_resource(
            mapper, example_controller,
            path=self.PATH_PREFIX + '/example',
            get_action='do_something',
            rel=build_resource_relation(resource_name='example'))

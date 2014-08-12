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

from keystone.common import wsgi
from keystone.contrib.endpoint_filter import controllers


class EndpointFilterExtension(wsgi.V3ExtensionRouter):

    PATH_PREFIX = '/OS-EP-FILTER'
    PATH_PROJECT_ENDPOINT = '/projects/{project_id}/endpoints/{endpoint_id}'

    def add_routes(self, mapper):
        endpoint_filter_controller = controllers.EndpointFilterV3Controller()

        self._add_resource(
            mapper, endpoint_filter_controller,
            path=self.PATH_PREFIX + '/endpoints/{endpoint_id}/projects',
            get_action='list_projects_for_endpoint')
        self._add_resource(
            mapper, endpoint_filter_controller,
            path=self.PATH_PREFIX + self.PATH_PROJECT_ENDPOINT,
            get_head_action='check_endpoint_in_project',
            put_action='add_endpoint_to_project',
            delete_action='remove_endpoint_from_project')
        self._add_resource(
            mapper, endpoint_filter_controller,
            path=self.PATH_PREFIX + '/projects/{project_id}/endpoints',
            get_action='list_endpoints_for_project')

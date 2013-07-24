# vim: tabstop=4 shiftwidth=4 softtabstop=4

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


class EndpointFilterExtension(wsgi.ExtensionRouter):

    PATH_PREFIX = '/OS-EP-FILTER'
    PATH_PROJECT_ENDPOINT = '/projects/{project_id}/endpoints/{endpoint_id}'

    def add_routes(self, mapper):
        endpoint_filter_controller = controllers.EndpointFilterV3Controller()
        mapper.connect(self.PATH_PREFIX + '/endpoints/{endpoint_id}/projects',
                       controller=endpoint_filter_controller,
                       action='list_projects_for_endpoint',
                       conditions=dict(method=['GET']))
        mapper.connect(self.PATH_PREFIX + self.PATH_PROJECT_ENDPOINT,
                       controller=endpoint_filter_controller,
                       action='add_endpoint_to_project',
                       conditions=dict(method=['PUT']))
        mapper.connect(self.PATH_PREFIX + self.PATH_PROJECT_ENDPOINT,
                       controller=endpoint_filter_controller,
                       action='check_endpoint_in_project',
                       conditions=dict(method=['HEAD']))
        mapper.connect(self.PATH_PREFIX + '/projects/{project_id}/endpoints',
                       controller=endpoint_filter_controller,
                       action='list_endpoints_for_project',
                       conditions=dict(method=['GET']))
        mapper.connect(self.PATH_PREFIX + self.PATH_PROJECT_ENDPOINT,
                       controller=endpoint_filter_controller,
                       action='remove_endpoint_from_project',
                       conditions=dict(method=['DELETE']))

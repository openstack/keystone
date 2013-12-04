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


from keystone.catalog import controllers as catalog_controllers
from keystone.common import controller
from keystone.common import dependency
from keystone.identity import controllers as identity_controllers


@dependency.requires('assignment_api', 'catalog_api', 'endpoint_filter_api')
class EndpointFilterV3Controller(controller.V3Controller):

    @controller.protected()
    def add_endpoint_to_project(self, context, project_id, endpoint_id):
        """Establishes an association between an endpoint and a project."""
        # NOTE(gyee): we just need to make sure endpoint and project exist
        # first. We don't really care whether if project is disabled.
        # The relationship can still be established even with a disabled
        # project as there are no security implications.
        self.catalog_api.get_endpoint(endpoint_id)
        self.assignment_api.get_project(project_id)
        # NOTE(gyee): we may need to cleanup any existing project-endpoint
        # associations here if either project or endpoint is not found.
        self.endpoint_filter_api.add_endpoint_to_project(endpoint_id,
                                                         project_id)

    @controller.protected()
    def check_endpoint_in_project(self, context, project_id, endpoint_id):
        """Verifies endpoint is currently associated with given project."""
        self.catalog_api.get_endpoint(endpoint_id)
        self.assignment_api.get_project(project_id)
        # TODO(gyee): we may need to cleanup any existing project-endpoint
        # associations here if either project or endpoint is not found.
        self.endpoint_filter_api.check_endpoint_in_project(endpoint_id,
                                                           project_id)

    @controller.protected()
    def list_endpoints_for_project(self, context, project_id):
        """Lists all endpoints currently associated with a given project."""
        self.assignment_api.get_project(project_id)
        refs = self.endpoint_filter_api.list_endpoints_for_project(project_id)

        endpoints = [self.catalog_api.get_endpoint(
            ref.endpoint_id) for ref in refs]
        return catalog_controllers.EndpointV3.wrap_collection(context,
                                                              endpoints)

    @controller.protected()
    def remove_endpoint_from_project(self, context, project_id, endpoint_id):
        """Remove the endpoint from the association with given project."""
        self.endpoint_filter_api.remove_endpoint_from_project(endpoint_id,
                                                              project_id)

    @controller.protected()
    def list_projects_for_endpoint(self, context, endpoint_id):
        """Return a list of projects associated with the endpoint."""
        refs = self.endpoint_filter_api.list_project_endpoints(endpoint_id)

        projects = [self.assignment_api.get_project(
            ref.project_id) for ref in refs]
        return identity_controllers.ProjectV3.wrap_collection(context,
                                                              projects)

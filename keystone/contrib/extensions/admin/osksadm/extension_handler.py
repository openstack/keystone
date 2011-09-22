# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from keystone.contrib.extensions.admin.extension import BaseExtensionHandler
from keystone.controllers.services import ServicesController
from keystone.controllers.roles import RolesController


class ExtensionHandler(BaseExtensionHandler):
    def map_extension_methods(self, mapper, options):
        # Services
        services_controller = ServicesController(options)
        mapper.connect("/OS-KSADM/services",
                    controller=services_controller,
                    action="get_services",
                    conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSADM/services",
                    controller=services_controller,
                    action="create_service",
                    conditions=dict(method=["POST"]))
        mapper.connect("/OS-KSADM/services/{service_id}",
                    controller=services_controller,
                    action="delete_service",
                    conditions=dict(method=["DELETE"]))
        mapper.connect("/OS-KSADM/services/{service_id}",
                    controller=services_controller,
                    action="get_service",
                    conditions=dict(method=["GET"]))
        #Roles
        roles_controller = RolesController(options)
        mapper.connect("/OS-KSADM/roles", controller=roles_controller,
                    action="create_role", conditions=dict(method=["POST"]))
        mapper.connect("/OS-KSADM/roles", controller=roles_controller,
                    action="get_roles", conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSADM/roles/{role_id}",
            controller=roles_controller, action="get_role",
                conditions=dict(method=["GET"]))
        mapper.connect("/OS-KSADM/roles/{role_id}",
            controller=roles_controller, action="delete_role",
            conditions=dict(method=["DELETE"]))

        #User Roles
        mapper.connect("/users/{user_id}/OS-KSADM/{role_id}",
            controller=roles_controller, action="add_global_role_to_user",
            conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}/roleRefs",
            controller=roles_controller, action="get_role_refs",
            conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/roleRefs",
            controller=roles_controller, action="create_role_ref",
            conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}/roleRefs/{role_ref_id}",
            controller=roles_controller, action="delete_role_ref",
            conditions=dict(method=["DELETE"]))

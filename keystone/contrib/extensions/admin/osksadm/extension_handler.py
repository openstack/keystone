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
from keystone.controllers.user import UserController
from keystone.controllers.tenant import TenantController
from keystone.controllers.credentials import CredentialsController


class ExtensionHandler(BaseExtensionHandler):
    def map_extension_methods(self, mapper, options):
        tenant_controller = TenantController(options)
        roles_controller = RolesController(options)
        user_controller = UserController(options)
        credentials_controller = CredentialsController(options)

        # Tenant Operations
        mapper.connect("/tenants", controller=tenant_controller,
                    action="create_tenant",
                    conditions=dict(method=["POST"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="update_tenant", conditions=dict(method=["POST"]))
        mapper.connect("/tenants/{tenant_id}",
                    controller=tenant_controller,
                    action="delete_tenant", conditions=dict(method=["DELETE"]))
        mapper.connect("/tenants/{tenant_id}/users",
                    controller=user_controller,
                    action="get_tenant_users",
                    conditions=dict(method=["GET"]))

        #Add/Delete Tenant specific role.
        mapper.connect(
            "/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=roles_controller, action="add_role_to_user",
            conditions=dict(method=["PUT"]))
        mapper.connect(
            "/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=roles_controller, action="delete_role_from_user",
            conditions=dict(method=["DELETE"]))
        # User Operations
        mapper.connect("/users",
                    controller=user_controller,
                    action="get_users",
                    conditions=dict(method=["GET"]))
        mapper.connect("/users",
                    controller=user_controller,
                    action="create_user",
                    conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="update_user",
                    conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}",
                    controller=user_controller,
                    action="delete_user",
                    conditions=dict(method=["DELETE"]))
        #API doesn't have any of the shorthand updates as of now.
        mapper.connect("/users/{user_id}/password",
                    controller=user_controller,
                    action="set_user_password",
                    conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/tenant",
                    controller=user_controller,
                    action="update_user_tenant",
                    conditions=dict(method=["PUT"]))
        # Test this, test failed
        mapper.connect("/users/{user_id}/enabled",
                    controller=user_controller,
                    action="set_user_enabled",
                    conditions=dict(method=["PUT"]))
        #User Roles
        #Add/Delete Global role.
        mapper.connect("/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=roles_controller, action="add_role_to_user",
            conditions=dict(method=["PUT"]))
        mapper.connect("/users/{user_id}/roles/OS-KSADM/{role_id}",
            controller=roles_controller, action="delete_role_from_user",
            conditions=dict(method=["DELETE"]))

        # Services Operations
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
        #Roles Operations
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

        #Credentials Operations
        mapper.connect("/users/{user_id}/OS-KSADM/credentials",
            controller=credentials_controller, action="get_credentials",
            conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/OS-KSADM/credentials",
            controller=credentials_controller, action="add_credential",
            conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}/OS-KSADM/"\
            "credentials/passwordCredentials",
            controller=credentials_controller,
            action="get_password_credential",
            conditions=dict(method=["GET"]))
        mapper.connect("/users/{user_id}/OS-KSADM/credentials"\
            "/passwordCredentials",
            controller=credentials_controller,
            action="update_password_credential",
            conditions=dict(method=["POST"]))
        mapper.connect("/users/{user_id}/"\
            "OS-KSADM/credentials/passwordCredentials",
            controller=credentials_controller,
            action="delete_password_credential",
            conditions=dict(method=["DELETE"]))

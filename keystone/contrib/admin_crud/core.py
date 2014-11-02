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

from keystone import assignment
from keystone import catalog
from keystone.common import extension
from keystone.common import wsgi
from keystone import identity
from keystone import resource


extension.register_admin_extension(
    'OS-KSADM', {
        'name': 'OpenStack Keystone Admin',
        'namespace': 'http://docs.openstack.org/identity/api/ext/'
                     'OS-KSADM/v1.0',
        'alias': 'OS-KSADM',
        'updated': '2013-07-11T17:14:00-00:00',
        'description': 'OpenStack extensions to Keystone v2.0 API '
                       'enabling Administrative Operations.',
        'links': [
            {
                'rel': 'describedby',
                # TODO(dolph): link needs to be revised after
                #              bug 928059 merges
                'type': 'text/html',
                'href': 'https://github.com/openstack/identity-api',
            }
        ]})


class CrudExtension(wsgi.ExtensionRouter):
    """Previously known as the OS-KSADM extension.

    Provides a bunch of CRUD operations for internal data types.

    """

    def add_routes(self, mapper):
        tenant_controller = resource.controllers.Tenant()
        assignment_tenant_controller = (
            assignment.controllers.TenantAssignment())
        user_controller = identity.controllers.User()
        role_controller = assignment.controllers.Role()
        assignment_role_controller = assignment.controllers.RoleAssignmentV2()
        service_controller = catalog.controllers.Service()
        endpoint_controller = catalog.controllers.Endpoint()

        # Tenant Operations
        mapper.connect(
            '/tenants',
            controller=tenant_controller,
            action='create_project',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/tenants/{tenant_id}',
            controller=tenant_controller,
            action='update_project',
            conditions=dict(method=['PUT', 'POST']))
        mapper.connect(
            '/tenants/{tenant_id}',
            controller=tenant_controller,
            action='delete_project',
            conditions=dict(method=['DELETE']))
        mapper.connect(
            '/tenants/{tenant_id}/users',
            controller=assignment_tenant_controller,
            action='get_project_users',
            conditions=dict(method=['GET']))

        # User Operations
        mapper.connect(
            '/users',
            controller=user_controller,
            action='get_users',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/users',
            controller=user_controller,
            action='create_user',
            conditions=dict(method=['POST']))
        # NOTE(termie): not in diablo
        mapper.connect(
            '/users/{user_id}',
            controller=user_controller,
            action='update_user',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/users/{user_id}',
            controller=user_controller,
            action='delete_user',
            conditions=dict(method=['DELETE']))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect(
            '/users/{user_id}/password',
            controller=user_controller,
            action='set_user_password',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/users/{user_id}/OS-KSADM/password',
            controller=user_controller,
            action='set_user_password',
            conditions=dict(method=['PUT']))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect(
            '/users/{user_id}/tenant',
            controller=user_controller,
            action='update_user',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/users/{user_id}/OS-KSADM/tenant',
            controller=user_controller,
            action='update_user',
            conditions=dict(method=['PUT']))

        # COMPAT(diablo): the copy with no OS-KSADM is from diablo
        mapper.connect(
            '/users/{user_id}/enabled',
            controller=user_controller,
            action='set_user_enabled',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/users/{user_id}/OS-KSADM/enabled',
            controller=user_controller,
            action='set_user_enabled',
            conditions=dict(method=['PUT']))

        # User Roles
        mapper.connect(
            '/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=assignment_role_controller,
            action='add_role_to_user',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=assignment_role_controller,
            action='remove_role_from_user',
            conditions=dict(method=['DELETE']))

        # COMPAT(diablo): User Roles
        mapper.connect(
            '/users/{user_id}/roleRefs',
            controller=assignment_role_controller,
            action='get_role_refs',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/users/{user_id}/roleRefs',
            controller=assignment_role_controller,
            action='create_role_ref',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/users/{user_id}/roleRefs/{role_ref_id}',
            controller=assignment_role_controller,
            action='delete_role_ref',
            conditions=dict(method=['DELETE']))

        # User-Tenant Roles
        mapper.connect(
            '/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=assignment_role_controller,
            action='add_role_to_user',
            conditions=dict(method=['PUT']))
        mapper.connect(
            '/tenants/{tenant_id}/users/{user_id}/roles/OS-KSADM/{role_id}',
            controller=assignment_role_controller,
            action='remove_role_from_user',
            conditions=dict(method=['DELETE']))

        # Service Operations
        mapper.connect(
            '/OS-KSADM/services',
            controller=service_controller,
            action='get_services',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/OS-KSADM/services',
            controller=service_controller,
            action='create_service',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/OS-KSADM/services/{service_id}',
            controller=service_controller,
            action='delete_service',
            conditions=dict(method=['DELETE']))
        mapper.connect(
            '/OS-KSADM/services/{service_id}',
            controller=service_controller,
            action='get_service',
            conditions=dict(method=['GET']))

        # Endpoint Templates
        mapper.connect(
            '/endpoints',
            controller=endpoint_controller,
            action='get_endpoints',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/endpoints',
            controller=endpoint_controller,
            action='create_endpoint',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/endpoints/{endpoint_id}',
            controller=endpoint_controller,
            action='delete_endpoint',
            conditions=dict(method=['DELETE']))

        # Role Operations
        mapper.connect(
            '/OS-KSADM/roles',
            controller=role_controller,
            action='create_role',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/OS-KSADM/roles',
            controller=role_controller,
            action='get_roles',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/OS-KSADM/roles/{role_id}',
            controller=role_controller,
            action='get_role',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/OS-KSADM/roles/{role_id}',
            controller=role_controller,
            action='delete_role',
            conditions=dict(method=['DELETE']))

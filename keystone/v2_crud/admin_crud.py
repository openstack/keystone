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
from keystone.common import extension
from keystone.common import wsgi
from keystone import identity


extension.register_admin_extension(
    'OS-KSADM', {
        'name': 'OpenStack Keystone Admin',
        'namespace': 'https://docs.openstack.org/identity/api/ext/'
                     'OS-KSADM/v1.0',
        'alias': 'OS-KSADM',
        'updated': '2013-07-11T17:14:00-00:00',
        'description': 'OpenStack extensions to Keystone v2.0 API '
                       'enabling Administrative Operations.',
        'links': [
            {
                'rel': 'describedby',
                'type': 'text/html',
                'href': 'https://developer.openstack.org/'
                        'api-ref-identity-v2-ext.html',
            }
        ]})


class Router(wsgi.ComposableRouter):
    """Previously known as the OS-KSADM extension.

    Provides a bunch of CRUD operations for internal data types.

    """

    def add_routes(self, mapper):
        assignment_tenant_controller = (
            assignment.controllers.TenantAssignment())
        user_controller = identity.controllers.User()

        # Tenant Operations
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

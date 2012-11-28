# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

"""WSGI Routers for the Identity service."""

import urllib
import urlparse
import uuid

from keystone.common import controller
from keystone.common import logging
from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import policy
from keystone import token
from keystone.identity import core, controllers


class PublicRouter(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        tenant_controller = controllers.TenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_tenants_for_token',
                       conditions=dict(method=['GET']))


class AdminRouter(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # Tenant Operations
        tenant_controller = controllers.TenantController()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_all_tenants',
                       conditions=dict(method=['GET']))
        mapper.connect('/tenants/{tenant_id}',
                       controller=tenant_controller,
                       action='get_tenant',
                       conditions=dict(method=['GET']))

        # User Operations
        user_controller = controllers.UserController()
        mapper.connect('/users/{user_id}',
                       controller=user_controller,
                       action='get_user',
                       conditions=dict(method=['GET']))

        # Role Operations
        roles_controller = controllers.RoleController()
        mapper.connect('/tenants/{tenant_id}/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))
        mapper.connect('/users/{user_id}/roles',
                       controller=roles_controller,
                       action='get_user_roles',
                       conditions=dict(method=['GET']))

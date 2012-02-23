# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2012 Canonical Ltd.
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

"""Main entry point into the Catalog service."""

import uuid

import webob.exc

from keystone import config
from keystone import identity
from keystone import policy
from keystone import token
from keystone.common import manager
from keystone.common import wsgi


CONF = config.CONF


class Manager(manager.Manager):
    """Default pivot point for the Catalog backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.catalog.driver)


class ServiceController(wsgi.Application):
    def __init__(self):
        self.catalog_api = Manager()
        super(ServiceController, self).__init__()

    # CRUD extensions
    # NOTE(termie): this OS-KSADM stuff is not very consistent
    def get_services(self, context):
        service_list = self.catalog_api.list_services(context)
        service_refs = [self.catalog_api.get_service(context, x)
                        for x in service_list]
        return {'OS-KSADM:services': service_refs}

    def get_service(self, context, service_id):
        service_ref = self.catalog_api.get_service(context, service_id)
        if not service_ref:
            raise webob.exc.HTTPNotFound()
        return {'OS-KSADM:service': service_ref}

    def delete_service(self, context, service_id):
        service_ref = self.catalog_api.delete_service(context, service_id)

    def create_service(self, context, OS_KSADM_service):
        service_id = uuid.uuid4().hex
        service_ref = OS_KSADM_service.copy()
        service_ref['id'] = service_id
        new_service_ref = self.catalog_api.create_service(
                context, service_id, service_ref)
        return {'OS-KSADM:service': new_service_ref}


class EndpointController(wsgi.Application):
    def __init__(self):
        self.catalog_api = Manager()
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(EndpointController, self).__init__()

    def get_endpoints(self, context):
        self.assert_admin(context)
        endpoint_list = self.catalog_api.list_endpoints(context)
        endpoint_refs = [self.catalog_api.get_endpoint(context, e)
                         for e in endpoint_list]
        return {'endpoints': endpoint_refs}

    def create_endpoint(self, context, endpoint):
        self.assert_admin(context)
        endpoint_id = uuid.uuid4().hex
        endpoint_ref = endpoint.copy()
        endpoint_ref['id'] = endpoint_id

        service_id = endpoint_ref['service_id']
        if not self.catalog_api.service_exists(context, service_id):
            msg = 'No service exists with id %s' % service_id
            raise webob.exc.HTTPBadRequest(msg)

        new_endpoint_ref = self.catalog_api.create_endpoint(
                                context, endpoint_id, endpoint_ref)
        return {'endpoint': new_endpoint_ref}

    def delete_endpoint(self, context, endpoint_id):
        self.assert_admin(context)
        endpoint_ref = self.catalog_api.delete_endpoint(context, endpoint_id)

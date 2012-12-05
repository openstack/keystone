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

import uuid

from keystone.catalog import core
from keystone.common import controller
from keystone.common import wsgi
from keystone import identity
from keystone import policy
from keystone import token


class Service(wsgi.Application):
    def __init__(self):
        self.catalog_api = core.Manager()
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(Service, self).__init__()

    def get_services(self, context):
        self.assert_admin(context)
        service_list = self.catalog_api.list_services(context)
        return {'OS-KSADM:services': service_list}

    def get_service(self, context, service_id):
        self.assert_admin(context)
        service_ref = self.catalog_api.get_service(context, service_id)
        return {'OS-KSADM:service': service_ref}

    def delete_service(self, context, service_id):
        self.assert_admin(context)
        self.catalog_api.delete_service(context, service_id)

    def create_service(self, context, OS_KSADM_service):
        self.assert_admin(context)
        service_id = uuid.uuid4().hex
        service_ref = OS_KSADM_service.copy()
        service_ref['id'] = service_id
        new_service_ref = self.catalog_api.create_service(
            context, service_id, service_ref)
        return {'OS-KSADM:service': new_service_ref}


class Endpoint(wsgi.Application):
    def __init__(self):
        self.catalog_api = core.Manager()
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(Endpoint, self).__init__()

    def get_endpoints(self, context):
        self.assert_admin(context)
        endpoint_list = self.catalog_api.list_endpoints(context)
        return {'endpoints': endpoint_list}

    def create_endpoint(self, context, endpoint):
        self.assert_admin(context)
        endpoint_id = uuid.uuid4().hex
        endpoint_ref = endpoint.copy()
        endpoint_ref['id'] = endpoint_id
        new_endpoint_ref = self.catalog_api.create_endpoint(
            context, endpoint_id, endpoint_ref)
        return {'endpoint': new_endpoint_ref}

    def delete_endpoint(self, context, endpoint_id):
        self.assert_admin(context)
        self.catalog_api.delete_endpoint(context, endpoint_id)


class ServiceV3(controller.V3Controller):
    @controller.protected
    def create_service(self, context, service):
        ref = self._assign_unique_id(self._normalize_dict(service))
        self._require_attribute(ref, 'type')

        ref = self.catalog_api.create_service(context, ref['id'], ref)
        return {'service': ref}

    @controller.protected
    def list_services(self, context):
        refs = self.catalog_api.list_services(context)
        refs = self._filter_by_attribute(context, refs, 'type')
        return {'services': self._paginate(context, refs)}

    @controller.protected
    def get_service(self, context, service_id):
        ref = self.catalog_api.get_service(context, service_id)
        return {'service': ref}

    @controller.protected
    def update_service(self, context, service_id, service):
        self._require_matching_id(service_id, service)

        ref = self.catalog_api.update_service(context, service_id, service)
        return {'service': ref}

    @controller.protected
    def delete_service(self, context, service_id):
        return self.catalog_api.delete_service(context, service_id)


class EndpointV3(controller.V3Controller):
    @controller.protected
    def create_endpoint(self, context, endpoint):
        ref = self._assign_unique_id(self._normalize_dict(endpoint))
        self._require_attribute(ref, 'service_id')
        self._require_attribute(ref, 'interface')
        self.catalog_api.get_service(context, ref['service_id'])

        ref = self.catalog_api.create_endpoint(context, ref['id'], ref)
        return {'endpoint': ref}

    @controller.protected
    def list_endpoints(self, context):
        refs = self.catalog_api.list_endpoints(context)
        refs = self._filter_by_attribute(context, refs, 'service_id')
        refs = self._filter_by_attribute(context, refs, 'interface')
        return {'endpoints': self._paginate(context, refs)}

    @controller.protected
    def get_endpoint(self, context, endpoint_id):
        ref = self.catalog_api.get_endpoint(context, endpoint_id)
        return {'endpoint': ref}

    @controller.protected
    def update_endpoint(self, context, endpoint_id, endpoint):
        self._require_matching_id(endpoint_id, endpoint)

        if 'service_id' in endpoint:
            self.catalog_api.get_service(context, endpoint['service_id'])

        ref = self.catalog_api.update_endpoint(context, endpoint_id, endpoint)
        return {'endpoint': ref}

    @controller.protected
    def delete_endpoint(self, context, endpoint_id):
        return self.catalog_api.delete_endpoint(context, endpoint_id)

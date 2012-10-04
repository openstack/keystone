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

from keystone.common import logging
from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import identity
from keystone import policy
from keystone import token


CONF = config.CONF
LOG = logging.getLogger(__name__)


def format_url(url, data):
    """Helper Method for all Backend Catalog's to Deal with URLS"""
    try:
        result = url.replace('$(', '%(') % data
    except AttributeError:
        return None
    except KeyError as e:
        LOG.error("Malformed endpoint %s - unknown key %s" %
                  (url, str(e)))
        raise exception.MalformedEndpoint(endpoint=url)
    except TypeError as e:
        LOG.error("Malformed endpoint %s - type mismatch %s \
                  (are you missing brackets ?)" %
                  (url, str(e)))
        raise exception.MalformedEndpoint(endpoint=url)
    except ValueError as e:
        LOG.error("Malformed endpoint %s - incomplete format \
                  (are you missing a type notifier ?)" % url)
        raise exception.MalformedEndpoint(endpoint=url)
    return result


class Manager(manager.Manager):
    """Default pivot point for the Catalog backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.catalog.driver)

    def get_service(self, context, service_id):
        try:
            return self.driver.get_service(service_id)
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    def delete_service(self, context, service_id):
        try:
            return self.driver.delete_service(service_id)
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    def create_endpoint(self, context, endpoint_id, endpoint_ref):
        try:
            return self.driver.create_endpoint(endpoint_id, endpoint_ref)
        except exception.NotFound:
            service_id = endpoint_ref.get('service_id')
            raise exception.ServiceNotFound(service_id=service_id)

    def delete_endpoint(self, context, endpoint_id):
        try:
            return self.driver.delete_endpoint(endpoint_id)
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_endpoint(self, context, endpoint_id):
        try:
            return self.driver.get_endpoint(endpoint_id)
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_catalog(self, context, user_id, tenant_id, metadata=None):
        try:
            return self.driver.get_catalog(user_id, tenant_id, metadata)
        except exception.NotFound:
            raise exception.NotFound('Catalog not found for user and tenant')


class Driver(object):
    """Interface description for an Catalog driver."""
    def list_services(self):
        """List all service ids in catalog.

        :returns: list of service_ids or an empty list.

        """
        raise exception.NotImplemented()

    def get_service(self, service_id):
        """Get service by id.

        :returns: service_ref dict
        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    def delete_service(self, service_id):
        """Deletes an existing service.

        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    def create_service(self, service_id, service_ref):
        """Creates a new service.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    def create_endpoint(self, endpoint_id, endpoint_ref):
        """Creates a new endpoint for a service.

        :raises: keystone.exception.Conflict,
                 keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    def delete_endpoint(self, endpoint_id):
        """Deletes an endpoint for a service.

        :raises: keystone.exception.EndpointNotFound

        """
        raise exception.NotImplemented()

    def get_endpoint(self, endpoint_id):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises: keystone.exception.EndpointNotFound

        """
        raise exception.NotImplemented()

    def list_endpoints(self):
        """List all endpoint ids in catalog.

        :returns: list of endpoint_ids or an empty list.

        """
        raise exception.NotImplemented()

    def get_catalog(self, user_id, tenant_id, metadata=None):
        """Retreive and format the current service catalog.

        Example::

            { 'RegionOne':
                {'compute': {
                    'adminURL': u'http://host:8774/v1.1/tenantid',
                    'internalURL': u'http://host:8774/v1.1/tenant_id',
                    'name': 'Compute Service',
                    'publicURL': u'http://host:8774/v1.1/tenantid'},
                 'ec2': {
                    'adminURL': 'http://host:8773/services/Admin',
                    'internalURL': 'http://host:8773/services/Cloud',
                    'name': 'EC2 Service',
                    'publicURL': 'http://host:8773/services/Cloud'}}

        :returns: A nested dict representing the service catalog or an
                  empty dict.
        :raises: keystone.exception.NotFound

        """
        raise exception.NotImplemented()


class ServiceController(wsgi.Application):
    def __init__(self):
        self.catalog_api = Manager()
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(ServiceController, self).__init__()

    # CRUD extensions
    # NOTE(termie): this OS-KSADM stuff is not very consistent
    def get_services(self, context):
        self.assert_admin(context)
        service_list = self.catalog_api.list_services(context)
        service_refs = [self.catalog_api.get_service(context, x)
                        for x in service_list]
        return {'OS-KSADM:services': service_refs}

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
        new_endpoint_ref = self.catalog_api.create_endpoint(
            context, endpoint_id, endpoint_ref)
        return {'endpoint': new_endpoint_ref}

    def delete_endpoint(self, context, endpoint_id):
        self.assert_admin(context)
        self.catalog_api.delete_endpoint(context, endpoint_id)

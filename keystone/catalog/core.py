# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

import abc

import six

from keystone.common import dependency
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone.openstack.common import log as logging


CONF = config.CONF
LOG = logging.getLogger(__name__)


def format_url(url, data):
    """Safely string formats a user-defined URL with the given data."""
    try:
        result = url.replace('$(', '%(') % data
    except AttributeError:
        return None
    except KeyError as e:
        LOG.error(_("Malformed endpoint %(url)s - unknown key %(keyerror)s"),
                  {"url": url,
                   "keyerror": e})
        raise exception.MalformedEndpoint(endpoint=url)
    except TypeError as e:
        LOG.error(_("Malformed endpoint %(url)s - unknown key %(keyerror)s"
                    "(are you missing brackets ?)"),
                  {"url": url,
                   "keyerror": e})
        raise exception.MalformedEndpoint(endpoint=url)
    except ValueError as e:
        LOG.error(_("Malformed endpoint %s - incomplete format "
                    "(are you missing a type notifier ?)"), url)
        raise exception.MalformedEndpoint(endpoint=url)
    return result


@dependency.provider('catalog_api')
class Manager(manager.Manager):
    """Default pivot point for the Catalog backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.catalog.driver)

    def get_service(self, service_id):
        try:
            return self.driver.get_service(service_id)
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    def delete_service(self, service_id):
        try:
            return self.driver.delete_service(service_id)
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    def create_endpoint(self, endpoint_id, endpoint_ref):
        try:
            return self.driver.create_endpoint(endpoint_id, endpoint_ref)
        except exception.NotFound:
            service_id = endpoint_ref.get('service_id')
            raise exception.ServiceNotFound(service_id=service_id)

    def delete_endpoint(self, endpoint_id):
        try:
            return self.driver.delete_endpoint(endpoint_id)
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_endpoint(self, endpoint_id):
        try:
            return self.driver.get_endpoint(endpoint_id)
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def get_catalog(self, user_id, tenant_id, metadata=None):
        try:
            return self.driver.get_catalog(user_id, tenant_id, metadata)
        except exception.NotFound:
            raise exception.NotFound('Catalog not found for user and tenant')


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Catalog driver."""

    @abc.abstractmethod
    def create_service(self, service_id, service_ref):
        """Creates a new service.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_services(self):
        """List all services.

        :returns: list of service_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_service(self, service_id):
        """Get service by id.

        :returns: service_ref dict
        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_service(self, service_id):
        """Update service by id.

        :returns: service_ref dict
        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_service(self, service_id):
        """Deletes an existing service.

        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_endpoint(self, endpoint_id, endpoint_ref):
        """Creates a new endpoint for a service.

        :raises: keystone.exception.Conflict,
                 keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_endpoint(self, endpoint_id):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises: keystone.exception.EndpointNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_endpoints(self):
        """List all endpoints.

        :returns: list of endpoint_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_endpoint(self, endpoint_id, endpoint_ref):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises: keystone.exception.EndpointNotFound
                 keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_endpoint(self, endpoint_id):
        """Deletes an endpoint for a service.

        :raises: keystone.exception.EndpointNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_catalog(self, user_id, tenant_id, metadata=None):
        """Retrieve and format the current service catalog.

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

    @abc.abstractmethod
    def get_v3_catalog(self, user_id, tenant_id, metadata=None):
        """Retrieve and format the current V3 service catalog.

        Example::

            [
                {
                    "endpoints": [
                    {
                        "interface": "public",
                        "id": "--endpoint-id--",
                        "region": "RegionOne",
                        "url": "http://external:8776/v1/--project-id--"
                    },
                    {
                        "interface": "internal",
                        "id": "--endpoint-id--",
                        "region": "RegionOne",
                        "url": "http://internal:8776/v1/--project-id--"
                    }],
                "id": "--service-id--",
                "type": "volume"
            }]

        :returns: A list representing the service catalog or an empty list
        :raises: keystone.exception.NotFound

        """
        raise exception.NotImplemented()

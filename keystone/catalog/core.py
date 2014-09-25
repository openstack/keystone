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
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)


def format_url(url, data):
    """Safely string formats a user-defined URL with the given data."""
    data = utils.WhiteListedFormatter(
        CONF.catalog.endpoint_substitution_whitelist,
        data)
    try:
        result = url.replace('$(', '%(') % data
    except AttributeError:
        LOG.error(_('Malformed endpoint - %(url)r is not a string'),
                  {"url": url})
        raise exception.MalformedEndpoint(endpoint=url)
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

    def create_region(self, region_ref):
        # Check duplicate ID
        try:
            self.get_region(region_ref['id'])
        except exception.RegionNotFound:
            pass
        else:
            msg = _('Duplicate ID, %s.') % region_ref['id']
            raise exception.Conflict(type='region', details=msg)

        try:
            return self.driver.create_region(region_ref)
        except exception.NotFound:
            parent_region_id = region_ref.get('parent_region_id')
            raise exception.RegionNotFound(region_id=parent_region_id)

    def get_region(self, region_id):
        try:
            return self.driver.get_region(region_id)
        except exception.NotFound:
            raise exception.RegionNotFound(region_id=region_id)

    def delete_region(self, region_id):
        try:
            return self.driver.delete_region(region_id)
        except exception.NotFound:
            raise exception.RegionNotFound(region_id=region_id)

    def create_service(self, service_id, service_ref):
        service_ref.setdefault('enabled', True)
        return self.driver.create_service(service_id, service_ref)

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

    @manager.response_truncated
    def list_services(self, hints=None):
        return self.driver.list_services(hints or driver_hints.Hints())

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

    @manager.response_truncated
    def list_endpoints(self, hints=None):
        return self.driver.list_endpoints(hints or driver_hints.Hints())

    def get_catalog(self, user_id, tenant_id, metadata=None):
        try:
            return self.driver.get_catalog(user_id, tenant_id, metadata)
        except exception.NotFound:
            raise exception.NotFound('Catalog not found for user and tenant')


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for an Catalog driver."""

    def _get_list_limit(self):
        return CONF.catalog.list_limit or CONF.list_limit

    @abc.abstractmethod
    def create_region(self, region_ref):
        """Creates a new region.

        :raises: keystone.exception.Conflict
        :raises: keystone.exception.RegionNotFound (if parent region invalid)

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_regions(self):
        """List all regions.

        :returns: list of region_refs or an empty list.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_region(self, region_id):
        """Get region by id.

        :returns: region_ref dict
        :raises: keystone.exception.RegionNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_region(self, region_id):
        """Update region by id.

        :returns: region_ref dict
        :raises: keystone.exception.RegionNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_region(self, region_id):
        """Deletes an existing region.

        :raises: keystone.exception.RegionNotFound

        """
        raise exception.NotImplemented()

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

    def get_v3_catalog(self, user_id, tenant_id, metadata=None):
        """Retrieve and format the current V3 service catalog.

        The default implementation builds the V3 catalog from the V2 catalog.

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
        v2_catalog = self.get_catalog(user_id, tenant_id, metadata=metadata)
        v3_catalog = []

        for region_name, region in six.iteritems(v2_catalog):
            for service_type, service in six.iteritems(region):
                service_v3 = {
                    'type': service_type,
                    'endpoints': []
                }

                for attr, value in six.iteritems(service):
                    # Attributes that end in URL are interfaces. In the V2
                    # catalog, these are internalURL, publicURL, and adminURL.
                    # For example, <region_name>.publicURL=<URL> in the V2
                    # catalog becomes the V3 interface for the service:
                    # { 'interface': 'public', 'url': '<URL>', 'region':
                    #   'region: '<region_name>' }
                    if attr.endswith('URL'):
                        v3_interface = attr[:-len('URL')]
                        service_v3['endpoints'].append({
                            'interface': v3_interface,
                            'region': region_name,
                            'url': value,
                        })
                        continue

                    # Other attributes are copied to the service.
                    service_v3[attr] = value

                v3_catalog.append(service_v3)

        return v3_catalog

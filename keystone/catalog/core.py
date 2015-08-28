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
import itertools

from oslo_config import cfg
from oslo_log import log
import six

from keystone.common import cache
from keystone.common import dependency
from keystone.common import driver_hints
from keystone.common import manager
from keystone.common import utils
from keystone import exception
from keystone.i18n import _
from keystone.i18n import _LE
from keystone import notifications


CONF = cfg.CONF
LOG = log.getLogger(__name__)
MEMOIZE = cache.get_memoization_decorator(section='catalog')
WHITELISTED_PROPERTIES = [
    'tenant_id', 'user_id', 'public_bind_host', 'admin_bind_host',
    'compute_host', 'admin_port', 'public_port',
    'public_endpoint', 'admin_endpoint', ]


def format_url(url, substitutions, silent_keyerror_failures=None):
    """Formats a user-defined URL with the given substitutions.

    :param string url: the URL to be formatted
    :param dict substitutions: the dictionary used for substitution
    :param list silent_keyerror_failures: keys for which we should be silent
        if there is a KeyError exception on substitution attempt
    :returns: a formatted URL

    """

    substitutions = utils.WhiteListedItemFilter(
        WHITELISTED_PROPERTIES,
        substitutions)
    allow_keyerror = silent_keyerror_failures or []
    try:
        result = url.replace('$(', '%(') % substitutions
    except AttributeError:
        LOG.error(_LE('Malformed endpoint - %(url)r is not a string'),
                  {"url": url})
        raise exception.MalformedEndpoint(endpoint=url)
    except KeyError as e:
        if not e.args or e.args[0] not in allow_keyerror:
            LOG.error(_LE("Malformed endpoint %(url)s - unknown key "
                          "%(keyerror)s"),
                      {"url": url,
                       "keyerror": e})
            raise exception.MalformedEndpoint(endpoint=url)
        else:
            result = None
    except TypeError as e:
        LOG.error(_LE("Malformed endpoint '%(url)s'. The following type error "
                      "occurred during string substitution: %(typeerror)s"),
                  {"url": url,
                   "typeerror": e})
        raise exception.MalformedEndpoint(endpoint=url)
    except ValueError as e:
        LOG.error(_LE("Malformed endpoint %s - incomplete format "
                      "(are you missing a type notifier ?)"), url)
        raise exception.MalformedEndpoint(endpoint=url)
    return result


def check_endpoint_url(url):
    """Check substitution of url.

    The invalid urls are as follows:
    urls with substitutions that is not in the whitelist

    Check the substitutions in the URL to make sure they are valid
    and on the whitelist.

    :param str url: the URL to validate
    :rtype: None
    :raises keystone.exception.URLValidationError: if the URL is invalid
    """
    # check whether the property in the path is exactly the same
    # with that in the whitelist below
    substitutions = dict(zip(WHITELISTED_PROPERTIES, itertools.repeat('')))
    try:
        url.replace('$(', '%(') % substitutions
    except (KeyError, TypeError, ValueError):
        raise exception.URLValidationError(url)


@dependency.provider('catalog_api')
class Manager(manager.Manager):
    """Default pivot point for the Catalog backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.catalog'

    _ENDPOINT = 'endpoint'
    _SERVICE = 'service'
    _REGION = 'region'

    def __init__(self):
        super(Manager, self).__init__(CONF.catalog.driver)

    def create_region(self, region_ref, initiator=None):
        # Check duplicate ID
        try:
            self.get_region(region_ref['id'])
        except exception.RegionNotFound:
            pass
        else:
            msg = _('Duplicate ID, %s.') % region_ref['id']
            raise exception.Conflict(type='region', details=msg)

        # NOTE(lbragstad,dstanek): The description column of the region
        # database cannot be null. So if the user doesn't pass in a
        # description or passes in a null description then set it to an
        # empty string.
        if region_ref.get('description') is None:
            region_ref['description'] = ''
        try:
            ret = self.driver.create_region(region_ref)
        except exception.NotFound:
            parent_region_id = region_ref.get('parent_region_id')
            raise exception.RegionNotFound(region_id=parent_region_id)

        notifications.Audit.created(self._REGION, ret['id'], initiator)
        return ret

    @MEMOIZE
    def get_region(self, region_id):
        try:
            return self.driver.get_region(region_id)
        except exception.NotFound:
            raise exception.RegionNotFound(region_id=region_id)

    def update_region(self, region_id, region_ref, initiator=None):
        # NOTE(lbragstad,dstanek): The description column of the region
        # database cannot be null. So if the user passes in a null
        # description set it to an empty string.
        if 'description' in region_ref and region_ref['description'] is None:
            region_ref['description'] = ''
        ref = self.driver.update_region(region_id, region_ref)
        notifications.Audit.updated(self._REGION, region_id, initiator)
        self.get_region.invalidate(self, region_id)
        return ref

    def delete_region(self, region_id, initiator=None):
        try:
            ret = self.driver.delete_region(region_id)
            notifications.Audit.deleted(self._REGION, region_id, initiator)
            self.get_region.invalidate(self, region_id)
            return ret
        except exception.NotFound:
            raise exception.RegionNotFound(region_id=region_id)

    @manager.response_truncated
    def list_regions(self, hints=None):
        return self.driver.list_regions(hints or driver_hints.Hints())

    def create_service(self, service_id, service_ref, initiator=None):
        service_ref.setdefault('enabled', True)
        service_ref.setdefault('name', '')
        ref = self.driver.create_service(service_id, service_ref)
        notifications.Audit.created(self._SERVICE, service_id, initiator)
        return ref

    @MEMOIZE
    def get_service(self, service_id):
        try:
            return self.driver.get_service(service_id)
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    def update_service(self, service_id, service_ref, initiator=None):
        ref = self.driver.update_service(service_id, service_ref)
        notifications.Audit.updated(self._SERVICE, service_id, initiator)
        self.get_service.invalidate(self, service_id)
        return ref

    def delete_service(self, service_id, initiator=None):
        try:
            endpoints = self.list_endpoints()
            ret = self.driver.delete_service(service_id)
            notifications.Audit.deleted(self._SERVICE, service_id, initiator)
            self.get_service.invalidate(self, service_id)
            for endpoint in endpoints:
                if endpoint['service_id'] == service_id:
                    self.get_endpoint.invalidate(self, endpoint['id'])
            return ret
        except exception.NotFound:
            raise exception.ServiceNotFound(service_id=service_id)

    @manager.response_truncated
    def list_services(self, hints=None):
        return self.driver.list_services(hints or driver_hints.Hints())

    def _assert_region_exists(self, region_id):
        try:
            if region_id is not None:
                self.get_region(region_id)
        except exception.RegionNotFound:
            raise exception.ValidationError(attribute='endpoint region_id',
                                            target='region table')

    def _assert_service_exists(self, service_id):
        try:
            if service_id is not None:
                self.get_service(service_id)
        except exception.ServiceNotFound:
            raise exception.ValidationError(attribute='endpoint service_id',
                                            target='service table')

    def create_endpoint(self, endpoint_id, endpoint_ref, initiator=None):
        self._assert_region_exists(endpoint_ref.get('region_id'))
        self._assert_service_exists(endpoint_ref['service_id'])
        ref = self.driver.create_endpoint(endpoint_id, endpoint_ref)

        notifications.Audit.created(self._ENDPOINT, endpoint_id, initiator)
        return ref

    def update_endpoint(self, endpoint_id, endpoint_ref, initiator=None):
        self._assert_region_exists(endpoint_ref.get('region_id'))
        self._assert_service_exists(endpoint_ref.get('service_id'))
        ref = self.driver.update_endpoint(endpoint_id, endpoint_ref)
        notifications.Audit.updated(self._ENDPOINT, endpoint_id, initiator)
        self.get_endpoint.invalidate(self, endpoint_id)
        return ref

    def delete_endpoint(self, endpoint_id, initiator=None):
        try:
            ret = self.driver.delete_endpoint(endpoint_id)
            notifications.Audit.deleted(self._ENDPOINT, endpoint_id, initiator)
            self.get_endpoint.invalidate(self, endpoint_id)
            return ret
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    @MEMOIZE
    def get_endpoint(self, endpoint_id):
        try:
            return self.driver.get_endpoint(endpoint_id)
        except exception.NotFound:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    @manager.response_truncated
    def list_endpoints(self, hints=None):
        return self.driver.list_endpoints(hints or driver_hints.Hints())

    def get_catalog(self, user_id, tenant_id):
        try:
            return self.driver.get_catalog(user_id, tenant_id)
        except exception.NotFound:
            raise exception.NotFound('Catalog not found for user and tenant')


@six.add_metaclass(abc.ABCMeta)
class CatalogDriverV8(object):
    """Interface description for the Catalog driver."""

    def _get_list_limit(self):
        return CONF.catalog.list_limit or CONF.list_limit

    def _ensure_no_circle_in_hierarchical_regions(self, region_ref):
        if region_ref.get('parent_region_id') is None:
            return

        root_region_id = region_ref['id']
        parent_region_id = region_ref['parent_region_id']

        while parent_region_id:
            # NOTE(wanghong): check before getting parent region can ensure no
            # self circle
            if parent_region_id == root_region_id:
                raise exception.CircularRegionHierarchyError(
                    parent_region_id=parent_region_id)
            parent_region = self.get_region(parent_region_id)
            parent_region_id = parent_region.get('parent_region_id')

    @abc.abstractmethod
    def create_region(self, region_ref):
        """Creates a new region.

        :raises: keystone.exception.Conflict
        :raises: keystone.exception.RegionNotFound (if parent region invalid)

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_regions(self, hints):
        """List all regions.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: list of region_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_region(self, region_id):
        """Get region by id.

        :returns: region_ref dict
        :raises: keystone.exception.RegionNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_region(self, region_id, region_ref):
        """Update region by id.

        :returns: region_ref dict
        :raises: keystone.exception.RegionNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_region(self, region_id):
        """Deletes an existing region.

        :raises: keystone.exception.RegionNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_service(self, service_id, service_ref):
        """Creates a new service.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_services(self, hints):
        """List all services.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: list of service_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_service(self, service_id):
        """Get service by id.

        :returns: service_ref dict
        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_service(self, service_id, service_ref):
        """Update service by id.

        :returns: service_ref dict
        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_service(self, service_id):
        """Deletes an existing service.

        :raises: keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_endpoint(self, endpoint_id, endpoint_ref):
        """Creates a new endpoint for a service.

        :raises: keystone.exception.Conflict,
                 keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_endpoint(self, endpoint_id):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises: keystone.exception.EndpointNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_endpoints(self, hints):
        """List all endpoints.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: list of endpoint_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_endpoint(self, endpoint_id, endpoint_ref):
        """Get endpoint by id.

        :returns: endpoint_ref dict
        :raises: keystone.exception.EndpointNotFound
                 keystone.exception.ServiceNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_endpoint(self, endpoint_id):
        """Deletes an endpoint for a service.

        :raises: keystone.exception.EndpointNotFound

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_catalog(self, user_id, tenant_id):
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
        raise exception.NotImplemented()  # pragma: no cover

    def get_v3_catalog(self, user_id, tenant_id):
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
        v2_catalog = self.get_catalog(user_id, tenant_id)
        v3_catalog = []

        for region_name, region in v2_catalog.items():
            for service_type, service in region.items():
                service_v3 = {
                    'type': service_type,
                    'endpoints': []
                }

                for attr, value in service.items():
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


Driver = manager.create_legacy_driver(CatalogDriverV8)

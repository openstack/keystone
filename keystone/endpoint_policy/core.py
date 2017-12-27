# Copyright 2014 IBM Corp.
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

from oslo_log import log

from keystone.common import manager
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class Manager(manager.Manager):
    """Default pivot point for the Endpoint Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.endpoint_policy'
    _provides_api = 'endpoint_policy_api'

    def __init__(self):
        super(Manager, self).__init__(CONF.endpoint_policy.driver)

    def _assert_valid_association(self, endpoint_id, service_id, region_id):
        """Assert that the association is supported.

        There are three types of association supported:

        - Endpoint (in which case service and region must be None)
        - Service and region (in which endpoint must be None)
        - Service (in which case endpoint and region must be None)

        """
        if (endpoint_id is not None and
                service_id is None and region_id is None):
            return
        if (service_id is not None and region_id is not None and
                endpoint_id is None):
            return
        if (service_id is not None and
                endpoint_id is None and region_id is None):
            return

        raise exception.InvalidPolicyAssociation(endpoint_id=endpoint_id,
                                                 service_id=service_id,
                                                 region_id=region_id)

    def create_policy_association(self, policy_id, endpoint_id=None,
                                  service_id=None, region_id=None):
        self._assert_valid_association(endpoint_id, service_id, region_id)
        self.driver.create_policy_association(policy_id, endpoint_id,
                                              service_id, region_id)

    def check_policy_association(self, policy_id, endpoint_id=None,
                                 service_id=None, region_id=None):
        self._assert_valid_association(endpoint_id, service_id, region_id)
        self.driver.check_policy_association(policy_id, endpoint_id,
                                             service_id, region_id)

    def delete_policy_association(self, policy_id, endpoint_id=None,
                                  service_id=None, region_id=None):
        self._assert_valid_association(endpoint_id, service_id, region_id)
        self.driver.delete_policy_association(policy_id, endpoint_id,
                                              service_id, region_id)

    def list_endpoints_for_policy(self, policy_id):

        def _get_endpoint(endpoint_id, policy_id):
            try:
                return PROVIDERS.catalog_api.get_endpoint(endpoint_id)
            except exception.EndpointNotFound:
                msg = ('Endpoint %(endpoint_id)s referenced in '
                       'association for policy %(policy_id)s not found.')
                LOG.warning(msg, {'policy_id': policy_id,
                                  'endpoint_id': endpoint_id})
                raise

        def _get_endpoints_for_service(service_id, endpoints):
            # TODO(henry-nash): Consider optimizing this in the future by
            # adding an explicit list_endpoints_for_service to the catalog API.
            return [ep for ep in endpoints if ep['service_id'] == service_id]

        def _get_endpoints_for_service_and_region(
                service_id, region_id, endpoints, regions):
            # TODO(henry-nash): Consider optimizing this in the future.
            # The lack of a two-way pointer in the region tree structure
            # makes this somewhat inefficient.

            def _recursively_get_endpoints_for_region(
                region_id, service_id, endpoint_list, region_list,
                    endpoints_found, regions_examined):
                """Recursively search down a region tree for endpoints.

                :param region_id: the point in the tree to examine
                :param service_id: the service we are interested in
                :param endpoint_list: list of all endpoints
                :param region_list: list of all regions
                :param endpoints_found: list of matching endpoints found so
                                        far - which will be updated if more are
                                        found in this iteration
                :param regions_examined: list of regions we have already looked
                                         at - used to spot illegal circular
                                         references in the tree to avoid never
                                         completing search
                :returns: list of endpoints that match

                """
                if region_id in regions_examined:
                    msg = ('Circular reference or a repeated entry found '
                           'in region tree - %(region_id)s.')
                    LOG.error(msg, {'region_id': ref.region_id})
                    return

                regions_examined.append(region_id)
                endpoints_found += (
                    [ep for ep in endpoint_list if
                     ep['service_id'] == service_id and
                     ep['region_id'] == region_id])

                for region in region_list:
                    if region['parent_region_id'] == region_id:
                        _recursively_get_endpoints_for_region(
                            region['id'], service_id, endpoints, regions,
                            endpoints_found, regions_examined)

            endpoints_found = []
            regions_examined = []

            # Now walk down the region tree
            _recursively_get_endpoints_for_region(
                region_id, service_id, endpoints, regions,
                endpoints_found, regions_examined)

            return endpoints_found

        matching_endpoints = []
        endpoints = PROVIDERS.catalog_api.list_endpoints()
        regions = PROVIDERS.catalog_api.list_regions()
        for ref in self.list_associations_for_policy(policy_id):
            if ref.get('endpoint_id') is not None:
                matching_endpoints.append(
                    _get_endpoint(ref['endpoint_id'], policy_id))
                continue

            if (ref.get('service_id') is not None and
                    ref.get('region_id') is None):
                matching_endpoints += _get_endpoints_for_service(
                    ref['service_id'], endpoints)
                continue

            if (ref.get('service_id') is not None and
                    ref.get('region_id') is not None):
                matching_endpoints += (
                    _get_endpoints_for_service_and_region(
                        ref['service_id'], ref['region_id'],
                        endpoints, regions))
                continue

            msg = ('Unsupported policy association found - '
                   'Policy %(policy_id)s, Endpoint %(endpoint_id)s, '
                   'Service %(service_id)s, Region %(region_id)s, ')
            LOG.warning(msg, {'policy_id': policy_id,
                              'endpoint_id': ref['endpoint_id'],
                              'service_id': ref['service_id'],
                              'region_id': ref['region_id']})

        return matching_endpoints

    def get_policy_for_endpoint(self, endpoint_id):

        def _get_policy(policy_id, endpoint_id):
            try:
                return PROVIDERS.policy_api.get_policy(policy_id)
            except exception.PolicyNotFound:
                msg = ('Policy %(policy_id)s referenced in association '
                       'for endpoint %(endpoint_id)s not found.')
                LOG.warning(msg, {'policy_id': policy_id,
                                  'endpoint_id': endpoint_id})
                raise

        def _look_for_policy_for_region_and_service(endpoint):
            """Look in the region and its parents for a policy.

            Examine the region of the endpoint for a policy appropriate for
            the service of the endpoint. If there isn't a match, then chase up
            the region tree to find one.

            """
            region_id = endpoint['region_id']
            regions_examined = []
            while region_id is not None:
                try:
                    ref = self.get_policy_association(
                        service_id=endpoint['service_id'],
                        region_id=region_id)
                    return ref['policy_id']
                except exception.PolicyAssociationNotFound:  # nosec
                    # There wasn't one for that region & service, handle below.
                    pass

                # There wasn't one for that region & service, let's
                # chase up the region tree
                regions_examined.append(region_id)
                region = PROVIDERS.catalog_api.get_region(region_id)
                region_id = None
                if region.get('parent_region_id') is not None:
                    region_id = region['parent_region_id']
                    if region_id in regions_examined:
                        msg = ('Circular reference or a repeated entry '
                               'found in region tree - %(region_id)s.')
                        LOG.error(msg, {'region_id': region_id})
                        break

        # First let's see if there is a policy explicitly defined for
        # this endpoint.

        try:
            ref = self.get_policy_association(endpoint_id=endpoint_id)
            return _get_policy(ref['policy_id'], endpoint_id)
        except exception.PolicyAssociationNotFound:  # nosec
            # There wasn't a policy explicitly defined for this endpoint,
            # handled below.
            pass

        # There wasn't a policy explicitly defined for this endpoint, so
        # now let's see if there is one for the Region & Service.

        endpoint = PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        policy_id = _look_for_policy_for_region_and_service(endpoint)
        if policy_id is not None:
            return _get_policy(policy_id, endpoint_id)

        # Finally, just check if there is one for the service.
        try:
            ref = self.get_policy_association(
                service_id=endpoint['service_id'])
            return _get_policy(ref['policy_id'], endpoint_id)
        except exception.PolicyAssociationNotFound:  # nosec
            # No policy is associated with endpoint, handled below.
            pass

        msg = _('No policy is associated with endpoint '
                '%(endpoint_id)s.') % {'endpoint_id': endpoint_id}
        raise exception.NotFound(msg)

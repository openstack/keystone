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

import itertools
import os.path

from oslo_log import log

from keystone.catalog.backends import base
from keystone.common import utils
import keystone.conf
from keystone import exception


LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF


def parse_templates(template_lines):
    o = {}
    for line in template_lines:
        if ' = ' not in line:
            continue

        k, v = line.strip().split(' = ')
        if not k.startswith('catalog.'):
            continue

        parts = k.split('.')

        region = parts[1]
        # NOTE(termie): object-store insists on having a dash
        service = parts[2].replace('_', '-')
        key = parts[3]

        region_ref = o.get(region, {})
        service_ref = region_ref.get(service, {})
        service_ref[key] = v

        region_ref[service] = service_ref
        o[region] = region_ref

    return o


class Catalog(base.CatalogDriverBase):
    """A backend that generates endpoints for the Catalog based on templates.

    It is usually configured via config entries that look like:

      catalog.$REGION.$SERVICE.$key = $value

    and is stored in a similar looking hierarchy. Where a value can contain
    values to be interpolated by standard python string interpolation that look
    like (the % is replaced by a $):

      http://localhost:$(public_port)s/

    When expanding the template it will pass in a dict made up of the conf
    instance plus a few additional key-values, notably project_id and user_id.

    It does not care what the keys and values are but it is worth noting that
    keystone_compat will expect certain keys to be there so that it can munge
    them into the output format keystone expects. These keys are:

      name - the name of the service, most likely repeated for all services of
             the same type, across regions.

      adminURL - the url of the admin endpoint

      publicURL - the url of the public endpoint

      internalURL - the url of the internal endpoint

    """

    def __init__(self, templates=None):
        super(Catalog, self).__init__()
        if templates:
            self.templates = templates
        else:
            template_file = CONF.catalog.template_file
            if not os.path.exists(template_file):
                template_file = CONF.find_file(template_file)
            self._load_templates(template_file)

    def _load_templates(self, template_file):
        try:
            with open(template_file) as f:
                self.templates = parse_templates(f)
        except IOError:
            LOG.critical('Unable to open template file %s', template_file)
            raise

    # region crud

    def create_region(self, region_ref):
        raise exception.NotImplemented()

    def list_regions(self, hints):
        return [{'id': region_id, 'description': '', 'parent_region_id': ''}
                for region_id in self.templates]

    def get_region(self, region_id):
        if region_id in self.templates:
            return {'id': region_id, 'description': '', 'parent_region_id': ''}
        raise exception.RegionNotFound(region_id=region_id)

    def update_region(self, region_id, region_ref):
        raise exception.NotImplemented()

    def delete_region(self, region_id):
        raise exception.NotImplemented()

    # service crud

    def create_service(self, service_id, service_ref):
        raise exception.NotImplemented()

    def _list_services(self, hints):
        for region_ref in self.templates.values():
            for service_type, service_ref in region_ref.items():
                yield {
                    'id': service_type,
                    'enabled': True,
                    'name': service_ref.get('name', ''),
                    'description': service_ref.get('description', ''),
                    'type': service_type,
                }

    def list_services(self, hints):
        return list(self._list_services(hints=None))

    def get_service(self, service_id):
        for service in self._list_services(hints=None):
            if service['id'] == service_id:
                return service
        raise exception.ServiceNotFound(service_id=service_id)

    def update_service(self, service_id, service_ref):
        raise exception.NotImplemented()

    def delete_service(self, service_id):
        raise exception.NotImplemented()

    # endpoint crud

    def create_endpoint(self, endpoint_id, endpoint_ref):
        raise exception.NotImplemented()

    def _list_endpoints(self):
        for region_id, region_ref in self.templates.items():
            for service_type, service_ref in region_ref.items():
                for key in service_ref:
                    if key.endswith('URL'):
                        interface = key[:-3]
                        endpoint_id = ('%s-%s-%s' %
                                       (region_id, service_type, interface))
                        yield {
                            'id': endpoint_id,
                            'service_id': service_type,
                            'interface': interface,
                            'url': service_ref[key],
                            'legacy_endpoint_id': None,
                            'region_id': region_id,
                            'enabled': True,
                        }

    def list_endpoints(self, hints):
        return list(self._list_endpoints())

    def get_endpoint(self, endpoint_id):
        for endpoint in self._list_endpoints():
            if endpoint['id'] == endpoint_id:
                return endpoint
        raise exception.EndpointNotFound(endpoint_id=endpoint_id)

    def update_endpoint(self, endpoint_id, endpoint_ref):
        raise exception.NotImplemented()

    def delete_endpoint(self, endpoint_id):
        raise exception.NotImplemented()

    def get_catalog(self, user_id, project_id):
        """Retrieve and format the V2 service catalog.

        :param user_id: The id of the user who has been authenticated for
            creating service catalog.
        :param project_id: The id of the project. 'project_id' will be None in
            the case this being called to create a catalog to go in a domain
            scoped token. In this case, any endpoint that requires a project_id
            as part of their URL will be skipped.

        :returns: A nested dict representing the service catalog or an
                  empty dict.

        """
        substitutions = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))
        substitutions.update({'user_id': user_id})
        silent_keyerror_failures = []
        if project_id:
            substitutions.update({
                'tenant_id': project_id,
                'project_id': project_id,
            })
        else:
            silent_keyerror_failures = ['tenant_id', 'project_id', ]

        catalog = {}
        # TODO(davechen): If there is service with no endpoints, we should
        # skip the service instead of keeping it in the catalog.
        # see bug #1436704.
        for region, region_ref in self.templates.items():
            catalog[region] = {}
            for service, service_ref in region_ref.items():
                service_data = {}
                try:
                    for k, v in service_ref.items():
                        formatted_value = utils.format_url(
                            v, substitutions,
                            silent_keyerror_failures=silent_keyerror_failures)
                        if formatted_value:
                            service_data[k] = formatted_value
                except exception.MalformedEndpoint:  # nosec(tkelsey)
                    continue  # this failure is already logged in format_url()
                catalog[region][service] = service_data

        return catalog

    def get_v3_catalog(self, user_id, project_id):
        """Retrieve and format the current V3 service catalog.

        This implementation builds the V3 catalog from the V2 catalog.

        :param user_id: The id of the user who has been authenticated for
            creating service catalog.
        :param project_id: The id of the project. 'project_id' will be None in
            the case this being called to create a catalog to go in a domain
            scoped token. In this case, any endpoint that requires a project_id
            as part of their URL will be skipped.

        :returns: A list representing the service catalog or an empty list

        """
        v2_catalog = self.get_catalog(user_id, project_id)
        v3_catalog = {}

        for region_name, region in v2_catalog.items():
            for service_type, service in region.items():
                if service_type not in v3_catalog:
                    v3_catalog[service_type] = {
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
                        v3_catalog[service_type]['endpoints'].append({
                            'interface': v3_interface,
                            'region': region_name,
                            'url': value,
                        })
                        continue

                    # Other attributes are copied to the service.
                    v3_catalog[service_type][attr] = value

        return list(v3_catalog.values())

    def add_endpoint_to_project(self, endpoint_id, project_id):
        raise exception.NotImplemented()

    def remove_endpoint_from_project(self, endpoint_id, project_id):
        raise exception.NotImplemented()

    def check_endpoint_in_project(self, endpoint_id, project_id):
        raise exception.NotImplemented()

    def list_endpoints_for_project(self, project_id):
        raise exception.NotImplemented()

    def list_projects_for_endpoint(self, endpoint_id):
        raise exception.NotImplemented()

    def delete_association_by_endpoint(self, endpoint_id):
        raise exception.NotImplemented()

    def delete_association_by_project(self, project_id):
        raise exception.NotImplemented()

    def create_endpoint_group(self, endpoint_group):
        raise exception.NotImplemented()

    def get_endpoint_group(self, endpoint_group_id):
        raise exception.NotImplemented()

    def update_endpoint_group(self, endpoint_group_id, endpoint_group):
        raise exception.NotImplemented()

    def delete_endpoint_group(self, endpoint_group_id):
        raise exception.NotImplemented()

    def add_endpoint_group_to_project(self, endpoint_group_id, project_id):
        raise exception.NotImplemented()

    def get_endpoint_group_in_project(self, endpoint_group_id, project_id):
        raise exception.NotImplemented()

    def list_endpoint_groups(self, hints):
        raise exception.NotImplemented()

    def list_endpoint_groups_for_project(self, project_id):
        raise exception.NotImplemented()

    def list_projects_associated_with_endpoint_group(self, endpoint_group_id):
        raise exception.NotImplemented()

    def remove_endpoint_group_from_project(self, endpoint_group_id,
                                           project_id):
        raise exception.NotImplemented()

    def delete_endpoint_group_association_by_project(self, project_id):
        raise exception.NotImplemented()

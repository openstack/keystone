# Copyright 2013 OpenStack Foundation
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

from oslo_config import cfg

from keystone.catalog.backends import sql
from keystone.catalog import core as catalog_core
from keystone.common import dependency
from keystone import exception


CONF = cfg.CONF


@dependency.requires('endpoint_filter_api')
class EndpointFilterCatalog(sql.Catalog):
    def get_v3_catalog(self, user_id, project_id):
        substitutions = dict(CONF.items())
        substitutions.update({'tenant_id': project_id, 'user_id': user_id})

        services = {}

        refs = self.endpoint_filter_api.list_endpoints_for_project(project_id)

        if (not refs and
                CONF.endpoint_filter.return_all_endpoints_if_no_filter):
            return super(EndpointFilterCatalog, self).get_v3_catalog(
                user_id, project_id)

        for entry in refs:
            try:
                endpoint = self.get_endpoint(entry['endpoint_id'])
                if not endpoint['enabled']:
                    # Skip disabled endpoints.
                    continue
                service_id = endpoint['service_id']
                services.setdefault(
                    service_id,
                    self.get_service(service_id))
                service = services[service_id]
                del endpoint['service_id']
                del endpoint['enabled']
                del endpoint['legacy_endpoint_id']
                endpoint['url'] = catalog_core.format_url(
                    endpoint['url'], substitutions)
                # populate filtered endpoints
                if 'endpoints' in services[service_id]:
                    service['endpoints'].append(endpoint)
                else:
                    service['endpoints'] = [endpoint]
            except exception.EndpointNotFound:
                # remove bad reference from association
                self.endpoint_filter_api.remove_endpoint_from_project(
                    entry['endpoint_id'], project_id)

        # format catalog
        catalog = []
        for service_id, service in services.items():
            formatted_service = {}
            formatted_service['id'] = service['id']
            formatted_service['type'] = service['type']
            formatted_service['endpoints'] = service['endpoints']
            catalog.append(formatted_service)

        return catalog

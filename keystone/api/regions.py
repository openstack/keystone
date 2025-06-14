#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This file handles all flask-restful resources for /v3/regions

import http.client

from keystone.api import validation
from keystone.catalog import schema
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask

ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


class RegionsResource(ks_flask.ResourceBase):
    collection_key = 'regions'
    member_key = 'region'

    @validation.request_query_schema(schema.regions_index_request_query)
    @validation.response_body_schema(schema.regions_index_response_body)
    def get(self):
        filters = ['parent_region_id']
        ENFORCER.enforce_call(action='identity:list_regions', filters=filters)
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.catalog_api.list_regions(hints)
        return self.wrap_collection(refs, hints=hints)

    @validation.request_body_schema(schema.region_create_request_body)
    @validation.response_body_schema(schema.region_show_response_body)
    def post(self):
        ENFORCER.enforce_call(action='identity:create_region')
        region = self.request_body_json.get('region')
        region = self._normalize_dict(region)
        if not region.get('id'):
            # NOTE(morgan): even though we officially only support 'id' setting
            # via the PUT mechanism, this is historical and we need to support
            # both ways.
            region = self._assign_unique_id(region)
        ref = PROVIDERS.catalog_api.create_region(
            region, initiator=self.audit_initiator
        )
        return self.wrap_member(ref), http.client.CREATED


class RegionResource(ks_flask.ResourceBase):
    collection_key = 'regions'
    member_key = 'region'

    @validation.request_body_schema(None)
    @validation.response_body_schema(schema.region_show_response_body)
    def get(self, region_id=None):
        ENFORCER.enforce_call(action='identity:get_region')
        return self.wrap_member(PROVIDERS.catalog_api.get_region(region_id))

    @validation.request_body_schema(schema.region_create_request_body)
    @validation.response_body_schema(schema.region_show_response_body)
    def put(self, region_id):
        ENFORCER.enforce_call(action='identity:create_region')
        region = self.request_body_json.get('region')
        region = self._normalize_dict(region)
        if 'id' not in region:
            region['id'] = region_id
        elif region_id != region.get('id'):
            raise exception.ValidationError(
                _(
                    'Conflicting region IDs specified: '
                    '"%(url_id)s" != "%(ref_id)s"'
                )
                % {'url_id': region_id, 'ref_id': region['id']}
            )

        ref = PROVIDERS.catalog_api.create_region(
            region, initiator=self.audit_initiator
        )
        return self.wrap_member(ref), http.client.CREATED

    @validation.request_body_schema(schema.region_update_request_body)
    @validation.response_body_schema(schema.region_show_response_body)
    def patch(self, region_id):
        ENFORCER.enforce_call(action='identity:update_region')
        region = self.request_body_json.get('region')
        self._require_matching_id(region)
        return self.wrap_member(
            PROVIDERS.catalog_api.update_region(
                region_id, region, initiator=self.audit_initiator
            )
        )

    @validation.request_body_schema(None)
    @validation.response_body_schema(None)
    def delete(self, region_id):
        ENFORCER.enforce_call(action='identity:delete_region')
        return (
            PROVIDERS.catalog_api.delete_region(
                region_id, initiator=self.audit_initiator
            ),
            http.client.NO_CONTENT,
        )


class RegionAPI(ks_flask.APIBase):
    _name = 'regions'
    _import_name = __name__
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=RegionsResource,
            url='/regions',
            resource_kwargs={},
            rel="regions",
            path_vars=None,
        ),
        ks_flask.construct_resource_map(
            resource=RegionResource,
            url='/regions/<string:region_id>',
            resource_kwargs={},
            rel="region",
            path_vars={
                'region_id': json_home.build_v3_parameter_relation("region_id")
            },
        ),
    ]


APIs = (RegionAPI,)

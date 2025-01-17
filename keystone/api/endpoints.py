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

# This file handles all flask-restful resources for /v3/services

import http.client

import flask_restful

from keystone.api._shared import json_home_relations
from keystone.api import validation
from keystone.catalog import schema
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import utils
from keystone import exception
from keystone import notifications
from keystone.server import flask as ks_flask

ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs

_resource_rel_func = json_home_relations.os_endpoint_policy_resource_rel_func


def _filter_endpoint(ref):
    ref.pop('legacy_endpoint_id', None)
    ref['region'] = ref['region_id']
    return ref


def _validate_endpoint_region(endpoint):
    """Ensure the region for the endpoint exists.

    If 'region_id' is used to specify the region, then we will let the
    manager/driver take care of this.  If, however, 'region' is used,
    then for backward compatibility, we will auto-create the region.

    """
    if (
        endpoint.get('region_id') is None
        and endpoint.get('region') is not None
    ):
        # To maintain backward compatibility with clients that are
        # using the v3 API in the same way as they used the v2 API,
        # create the endpoint region, if that region does not exist
        # in keystone.
        endpoint['region_id'] = endpoint.pop('region')
        try:
            PROVIDERS.catalog_api.get_region(endpoint['region_id'])
        except exception.RegionNotFound:
            region = {'id': endpoint['region_id']}
            PROVIDERS.catalog_api.create_region(
                region, initiator=notifications.build_audit_initiator()
            )
    return endpoint


class EndpointsResource(ks_flask.ResourceBase):
    collection_key = 'endpoints'
    member_key = 'endpoint'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='catalog_api', method='get_endpoint'
    )

    @validation.request_query_schema(schema.endpoint_index_request_query)
    @validation.response_body_schema(schema.endpoint_index_response_body)
    def get(self):
        """List all endpoints.

        GET /v3/endpoints
        """
        filters = ['interface', 'service_id', 'region_id']
        ENFORCER.enforce_call(
            action='identity:list_endpoints', filters=filters
        )
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.catalog_api.list_endpoints(hints=hints)
        return self.wrap_collection(
            [_filter_endpoint(r) for r in refs], hints=hints
        )

    @validation.request_body_schema(schema.endpoint_create_request_body)
    @validation.response_body_schema(schema.endpoint_response_body)
    def post(self):
        """Create new endpoints.

        POST /v3/endpoints
        """
        ENFORCER.enforce_call(action='identity:create_endpoint')
        endpoint = self.request_body_json.get('endpoint')
        utils.check_endpoint_url(endpoint['url'])
        endpoint = self._assign_unique_id(self._normalize_dict(endpoint))
        endpoint = _validate_endpoint_region(endpoint)
        ref = PROVIDERS.catalog_api.create_endpoint(
            endpoint['id'], endpoint, initiator=self.audit_initiator
        )
        return self.wrap_member(_filter_endpoint(ref)), http.client.CREATED


class EndpointResource(ks_flask.ResourceBase):
    collection_key = 'endpoints'
    member_key = 'endpoint'

    @validation.request_query_schema(schema.endpoint_request_query)
    @validation.response_body_schema(schema.endpoint_response_body)
    def get(self, endpoint_id):
        """Show endpoint details

        GET /v3/endpoints/{endpoint_id}
        """
        ENFORCER.enforce_call(action='identity:get_endpoint')
        return self.wrap_member(
            _filter_endpoint(PROVIDERS.catalog_api.get_endpoint(endpoint_id))
        )

    @validation.request_body_schema(schema.endpoint_update_request_body)
    @validation.response_body_schema(schema.endpoint_response_body)
    def patch(self, endpoint_id):
        """Update existing endpoints.

        PATCH /v3/endpoints/{endpoint_id}
        """
        ENFORCER.enforce_call(action='identity:update_endpoint')
        endpoint = self.request_body_json.get('endpoint')
        self._require_matching_id(endpoint)
        endpoint = _validate_endpoint_region(endpoint)
        ref = PROVIDERS.catalog_api.update_endpoint(
            endpoint_id, endpoint, initiator=self.audit_initiator
        )
        return self.wrap_member(_filter_endpoint(ref))

    def delete(self, endpoint_id):
        ENFORCER.enforce_call(action='identity:delete_endpoint')
        PROVIDERS.catalog_api.delete_endpoint(
            endpoint_id, initiator=self.audit_initiator
        )
        return None, http.client.NO_CONTENT


class EndpointPolicyEndpointResource(flask_restful.Resource):
    def get(self, endpoint_id):
        ENFORCER.enforce_call(action='identity:get_policy_for_endpoint')
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        ref = PROVIDERS.endpoint_policy_api.get_policy_for_endpoint(
            endpoint_id
        )
        return ks_flask.ResourceBase.wrap_member(
            ref, collection_name='endpoints', member_name='policy'
        )


class EndpointAPI(ks_flask.APIBase):
    _name = 'endpoints'
    _import_name = __name__
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=EndpointsResource,
            url='/endpoints',
            resource_kwargs={},
            rel="endpoints",
            path_vars=None,
        ),
        ks_flask.construct_resource_map(
            resource=EndpointResource,
            url='/endpoints/<string:endpoint_id>',
            resource_kwargs={},
            rel="endpoint",
            path_vars={'endpoint_id': json_home.Parameters.ENDPOINT_ID},
        ),
        ks_flask.construct_resource_map(
            resource=EndpointPolicyEndpointResource,
            url='/endpoints/<string:endpoint_id>/OS-ENDPOINT-POLICY/policy',
            resource_kwargs={},
            rel='endpoint_policy',
            resource_relation_func=_resource_rel_func,
            path_vars={'endpoint_id': json_home.Parameters.ENDPOINT_ID},
        ),
    ]


APIs = (EndpointAPI,)

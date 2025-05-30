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

# This file handles all flask-restful resources for /v3/registered_limits

import http.client

import flask

from keystone.api import validation
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.limit import schema
from keystone.server import flask as ks_flask

PROVIDERS = provider_api.ProviderAPIs
ENFORCER = rbac_enforcer.RBACEnforcer


class RegisteredLimitsResource(ks_flask.ResourceBase):
    collection_key = 'registered_limits'
    member_key = 'registered_limit'
    json_home_resource_status = json_home.Status.EXPERIMENTAL

    @validation.request_query_schema(
        schema.registered_limits_index_request_query
    )
    @validation.response_body_schema(
        schema.registered_limits_index_response_body
    )
    def get(self):
        """List registered limits.

        GET /v3/registered_limits
        """
        filters = ['service_id', 'region_id', 'resource_name']
        ENFORCER.enforce_call(
            action='identity:list_registered_limits', filters=filters
        )
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.unified_limit_api.list_registered_limits(hints)
        return self.wrap_collection(refs, hints=hints)

    @validation.request_body_schema(
        schema.registered_limits_create_request_body
    )
    @validation.response_body_schema(
        schema.registered_limits_create_response_body
    )
    def post(self):
        """Create new registered limits.

        POST /v3/registered_limits
        """
        ENFORCER.enforce_call(action='identity:create_registered_limits')
        reg_limits = (
            flask.request.get_json(silent=True, force=True) or {}
        ).get('registered_limits', {})
        registered_limits = [
            self._assign_unique_id(self._normalize_dict(r)) for r in reg_limits
        ]
        refs = PROVIDERS.unified_limit_api.create_registered_limits(
            registered_limits
        )
        refs = self.wrap_collection(refs)
        refs.pop('links')
        return refs, http.client.CREATED


class RegisteredLimitResource(ks_flask.ResourceBase):
    collection_key = 'registered_limits'
    member_key = 'registered_limit'
    json_home_resource_status = json_home.Status.EXPERIMENTAL

    @validation.request_body_schema(None)
    @validation.response_body_schema(
        schema.registered_limit_show_response_body
    )
    def get(self, registered_limit_id=None):
        """Retrieve an existing registered limit.

        GET /v3/registered_limits/{registered_limit_id}
        """
        ENFORCER.enforce_call(action='identity:get_registered_limit')
        ref = PROVIDERS.unified_limit_api.get_registered_limit(
            registered_limit_id
        )
        return self.wrap_member(ref)

    @validation.request_body_schema(
        schema.registered_limit_update_request_body
    )
    @validation.response_body_schema(
        schema.registered_limit_show_response_body
    )
    def patch(self, registered_limit_id):
        """Update an existing registered limit.

        PATCH /v3/registered_limits/{registered_limit_id}
        """
        ENFORCER.enforce_call(action='identity:update_registered_limit')
        registered_limit = (
            flask.request.get_json(silent=True, force=True) or {}
        ).get('registered_limit', {})
        self._require_matching_id(registered_limit)
        ref = PROVIDERS.unified_limit_api.update_registered_limit(
            registered_limit_id, registered_limit
        )
        return self.wrap_member(ref)

    @validation.request_body_schema(None)
    @validation.response_body_schema(None)
    def delete(self, registered_limit_id):
        """Delete a registered limit.

        DELETE /v3/registered_limits/{registered_limit_id}
        """
        ENFORCER.enforce_call(action='identity:delete_registered_limit')
        return (
            PROVIDERS.unified_limit_api.delete_registered_limit(
                registered_limit_id
            ),
            http.client.NO_CONTENT,
        )


class RegisteredLimitsAPI(ks_flask.APIBase):
    _name = 'registered_limits'
    _import_name = __name__
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=RegisteredLimitsResource,
            url='/registered_limits',
            resource_kwargs={},
            rel="registered_limits",
            path_vars=None,
            status=json_home.Status.EXPERIMENTAL,
        ),
        ks_flask.construct_resource_map(
            resource=RegisteredLimitResource,
            url='/registered_limits/<string:registered_limit_id>',
            resource_kwargs={},
            rel="registered_limit",
            path_vars={
                'registered_limit_id': json_home.build_v3_parameter_relation(
                    "registered_limit_id"
                )
            },
            status=json_home.Status.EXPERIMENTAL,
        ),
    ]


APIs = (RegisteredLimitsAPI,)

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

# This file handles all flask-restful resources for /v3/limits

import http.client

import flask
import flask_restful

from keystone.api import validation
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone import exception
from keystone.limit import schema
from keystone.server import flask as ks_flask

PROVIDERS = provider_api.ProviderAPIs
ENFORCER = rbac_enforcer.RBACEnforcer


def _build_limit_enforcement_target():
    target = {}
    try:
        limit = PROVIDERS.unified_limit_api.get_limit(
            flask.request.view_args.get('limit_id')
        )
        target['limit'] = limit
        if limit.get('project_id'):
            project = PROVIDERS.resource_api.get_project(limit['project_id'])
            target['limit']['project'] = project
        elif limit.get('domain_id'):
            domain = PROVIDERS.resource_api.get_domain(limit['domain_id'])
            target['limit']['domain'] = domain
    except exception.NotFound:  # nosec
        # Defer the existence check in the event the limit doesn't exist, this
        # is checked later anyway.
        pass

    return target


class LimitsResource(ks_flask.ResourceBase):
    collection_key = 'limits'
    member_key = 'limit'
    json_home_resource_status = json_home.Status.EXPERIMENTAL
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='unified_limit_api', method='get_limit'
    )

    @validation.request_query_schema(schema.limits_index_request_query)
    @validation.response_body_schema(schema.limits_index_response_body)
    def get(self):
        """List limits.

        GET /v3/limits
        """
        filters = [
            'service_id',
            'region_id',
            'resource_name',
            'project_id',
            'domain_id',
        ]

        ENFORCER.enforce_call(action='identity:list_limits', filters=filters)

        hints = self.build_driver_hints(filters)

        filtered_refs = []
        if self.oslo_context.system_scope:
            refs = PROVIDERS.unified_limit_api.list_limits(hints)
            filtered_refs = refs
        elif self.oslo_context.domain_id:
            refs = PROVIDERS.unified_limit_api.list_limits(hints)
            projects = PROVIDERS.resource_api.list_projects_in_domain(
                self.oslo_context.domain_id
            )
            project_ids = [project['id'] for project in projects]
            for limit in refs:
                if limit.get('project_id'):
                    if limit['project_id'] in project_ids:
                        filtered_refs.append(limit)
                elif limit.get('domain_id'):
                    if limit['domain_id'] == self.oslo_context.domain_id:
                        filtered_refs.append(limit)
        elif self.oslo_context.project_id:
            hints.add_filter('project_id', self.oslo_context.project_id)
            refs = PROVIDERS.unified_limit_api.list_limits(hints)
            filtered_refs = refs

        return self.wrap_collection(filtered_refs, hints=hints)

    @validation.request_body_schema(schema.limits_create_request_body)
    @validation.response_body_schema(schema.limits_create_response_body)
    def post(self):
        """Create new limits.

        POST /v3/limits
        """
        ENFORCER.enforce_call(action='identity:create_limits')
        limits_b = (flask.request.get_json(silent=True, force=True) or {}).get(
            'limits', {}
        )
        limits = [
            self._assign_unique_id(self._normalize_dict(limit))
            for limit in limits_b
        ]
        refs = PROVIDERS.unified_limit_api.create_limits(limits)
        refs = self.wrap_collection(refs)
        refs.pop('links')
        return refs, http.client.CREATED


class LimitResource(ks_flask.ResourceBase):
    collection_key = 'limits'
    member_key = 'limit'
    json_home_resource_status = json_home.Status.EXPERIMENTAL
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='unified_limit_api', method='get_limit'
    )

    @validation.request_body_schema(None)
    @validation.response_body_schema(schema.limit_show_response_body)
    def get(self, limit_id):
        """Retrieve an existing limit.

        GET /v3/limits/{limit_id}
        """
        ENFORCER.enforce_call(
            action='identity:get_limit',
            build_target=_build_limit_enforcement_target,
        )
        ref = PROVIDERS.unified_limit_api.get_limit(limit_id)
        return self.wrap_member(ref)

    @validation.request_body_schema(schema.limit_update_request_body)
    @validation.response_body_schema(schema.limit_show_response_body)
    def patch(self, limit_id):
        """Update an existing limit.

        PATCH /v3/limits/{limit_id}
        """
        ENFORCER.enforce_call(action='identity:update_limit')
        limit = (flask.request.get_json(silent=True, force=True) or {}).get(
            'limit', {}
        )
        self._require_matching_id(limit)
        ref = PROVIDERS.unified_limit_api.update_limit(limit_id, limit)
        return self.wrap_member(ref)

    @validation.request_body_schema(None)
    @validation.response_body_schema(None)
    def delete(self, limit_id):
        """Delete a limit.

        DELETE /v3/limits/{limit_id}
        """
        ENFORCER.enforce_call(action='identity:delete_limit')
        return (
            PROVIDERS.unified_limit_api.delete_limit(limit_id),
            http.client.NO_CONTENT,
        )


class LimitModelResource(flask_restful.Resource):
    @validation.request_body_schema(None)
    @validation.response_body_schema(schema.limit_model_show_response_body)
    def get(self):
        """Retrieve enforcement model.

        GET /v3/limits/model
        """
        ENFORCER.enforce_call(action='identity:get_limit_model')
        model = PROVIDERS.unified_limit_api.get_model()
        return {'model': model}


class LimitsAPI(ks_flask.APIBase):
    _name = 'limits'
    _import_name = __name__
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=LimitsResource,
            url='/limits',
            resource_kwargs={},
            rel="limits",
            path_vars=None,
            status=json_home.Status.EXPERIMENTAL,
        ),
        ks_flask.construct_resource_map(
            resource=LimitResource,
            url='/limits/<string:limit_id>',
            resource_kwargs={},
            rel="limit",
            path_vars={
                'limit_id': json_home.build_v3_parameter_relation("limit_id")
            },
            status=json_home.Status.EXPERIMENTAL,
        ),
        ks_flask.construct_resource_map(
            resource=LimitModelResource,
            resource_kwargs={},
            url='/limits/model',
            rel='limit_model',
            status=json_home.Status.EXPERIMENTAL,
        ),
    ]


APIs = (LimitsAPI,)

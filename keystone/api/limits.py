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

import flask
import flask_restful
from six.moves import http_client

from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
from keystone import exception
from keystone.i18n import _
from keystone.limit import schema
from keystone.server import flask as ks_flask


PROVIDERS = provider_api.ProviderAPIs
ENFORCER = rbac_enforcer.RBACEnforcer


class LimitsResource(ks_flask.ResourceBase):
    collection_key = 'limits'
    member_key = 'limit'
    json_home_resource_status = json_home.Status.EXPERIMENTAL

    def _list_limits(self):
        filters = ['service_id', 'region_id', 'resource_name', 'project_id']
        ENFORCER.enforce_call(action='identity:list_limits', filters=filters)
        hints = self.build_driver_hints(filters)
        project_id_filter = hints.get_exact_filter_by_name('project_id')
        if project_id_filter:
            if self.oslo_context.system_scope:
                refs = PROVIDERS.unified_limit_api.list_limits(hints)
            else:
                refs = []
        else:
            project_id = self.oslo_context.project_id
            if project_id:
                hints.add_filter('project_id', project_id)
            refs = PROVIDERS.unified_limit_api.list_limits(hints)
        return self.wrap_collection(refs, hints=hints)

    def _get_limit(self, limit_id):
        ENFORCER.enforce_call(action='identity:get_limit')
        ref = PROVIDERS.unified_limit_api.get_limit(limit_id)
        if (not self.oslo_context.is_admin and
                not ('admin' in self.oslo_context.roles)):
            project_id = self.oslo_context.project_id
            if project_id and project_id != ref['project_id']:
                action = _('The authenticated project should match the '
                           'project_id')
                raise exception.Forbidden(action=action)
        return self.wrap_member(ref)

    def get(self, limit_id=None):
        if limit_id is not None:
            return self._get_limit(limit_id)
        return self._list_limits()

    def post(self):
        ENFORCER.enforce_call(action='identity:create_limits')
        limits_b = (flask.request.get_json(silent=True, force=True) or {}).get(
            'limits', {})
        validation.lazy_validate(schema.limit_create, limits_b)
        limits = [self._assign_unique_id(self._normalize_dict(limit))
                  for limit in limits_b]
        refs = PROVIDERS.unified_limit_api.create_limits(limits)
        refs = self.wrap_collection(refs)
        refs.pop('links')
        return refs, http_client.CREATED

    def patch(self, limit_id):
        ENFORCER.enforce_call(action='identity:update_limit')
        limit = (flask.request.get_json(silent=True, force=True) or {}).get(
            'limit', {})
        validation.lazy_validate(schema.limit_update, limit)
        self._require_matching_id(limit)
        ref = PROVIDERS.unified_limit_api.update_limit(limit_id, limit)
        return self.wrap_member(ref)

    def delete(self, limit_id):
        ENFORCER.enforce_call(action='identity:delete_limit')
        return (PROVIDERS.unified_limit_api.delete_limit(limit_id),
                http_client.NO_CONTENT)


class LimitModelResource(flask_restful.Resource):
    def get(self):
        ENFORCER.enforce_call(action='identity:get_limit_model')
        model = PROVIDERS.unified_limit_api.get_model()
        return {'model': model}


class LimitsAPI(ks_flask.APIBase):
    _name = 'limits'
    _import_name = __name__
    resources = [LimitsResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=LimitModelResource,
            resource_kwargs={},
            url='/limits/model',
            rel='limit_model',
            status=json_home.Status.EXPERIMENTAL
        )
    ]


APIs = (LimitsAPI,)

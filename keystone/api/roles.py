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

# This file handles all flask-restful resources for /v3/roles

import flask
import flask_restful
import http.client

from keystone.api._shared import implied_roles as shared
from keystone.assignment import schema
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
import keystone.conf
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


class RoleResource(ks_flask.ResourceBase):
    collection_key = 'roles'
    member_key = 'role'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='role_api', method='get_role')

    def _is_domain_role(self, role):
        return bool(role.get('domain_id'))

    def get(self, role_id=None):
        """Get role or list roles.

        GET/HEAD /v3/roles
        GET/HEAD /v3/roles/{role_id}
        """
        if role_id is not None:
            return self._get_role(role_id)
        return self._list_roles()

    def _get_role(self, role_id):
        err = None
        role = {}
        try:
            role = PROVIDERS.role_api.get_role(role_id)
        except Exception as e:  # nosec
            # We don't raise out here, we raise out after enforcement, this
            # ensures we do not leak role existence. Do nothing yet, process
            # enforcement before raising out an error.
            err = e
        finally:
            # NOTE(morgan): There are a couple of cases to be aware of here
            # if there is an exception (e is not None), then we are enforcing
            # on "get_role" to be safe. If the role is not a "domain_role",
            # we are enforcing on "get_role". If the role is "domain_role" we
            # are inforcing on "get_domain_role"
            if err is not None or not self._is_domain_role(role):
                ENFORCER.enforce_call(action='identity:get_role')
                if err:
                    # reraise the error after enforcement if needed.
                    raise err
            else:
                ENFORCER.enforce_call(action='identity:get_domain_role',
                                      member_target_type='role',
                                      member_target=role)
        return self.wrap_member(role)

    def _list_roles(self):
        filters = ['name', 'domain_id']
        domain_filter = flask.request.args.get('domain_id')
        if domain_filter:
            ENFORCER.enforce_call(action='identity:list_domain_roles',
                                  filters=filters)
        else:
            ENFORCER.enforce_call(action='identity:list_roles',
                                  filters=filters)

        hints = self.build_driver_hints(filters)
        if not domain_filter:
            # NOTE(jamielennox): To handle the default case of not domain_id
            # defined the role_assignment backend does some hackery to
            # distinguish between global and domain scoped roles. This backend
            # behaviour relies upon a value of domain_id being set (not just
            # defaulting to None). Manually set the filter if its not
            # provided.
            hints.add_filter('domain_id', None)
        refs = PROVIDERS.role_api.list_roles(hints=hints)
        return self.wrap_collection(refs, hints=hints)

    def post(self):
        """Create role.

        POST /v3/roles
        """
        role = self.request_body_json.get('role', {})
        if self._is_domain_role(role):
            ENFORCER.enforce_call(action='identity:create_domain_role')
        else:
            ENFORCER.enforce_call(action='identity:create_role')
        validation.lazy_validate(schema.role_create, role)
        role = self._assign_unique_id(role)
        role = self._normalize_dict(role)
        ref = PROVIDERS.role_api.create_role(
            role['id'], role, initiator=self.audit_initiator)
        return self.wrap_member(ref), http.client.CREATED

    def patch(self, role_id):
        """Update role.

        PATCH /v3/roles/{role_id}
        """
        err = None
        role = {}
        try:
            role = PROVIDERS.role_api.get_role(role_id)
        except Exception as e:  # nosec
            # We don't raise out here, we raise out after enforcement, this
            # ensures we do not leak role existence. Do nothing yet, process
            # enforcement before raising out an error.
            err = e
        finally:
            if err is not None or not self._is_domain_role(role):
                ENFORCER.enforce_call(action='identity:update_role')
                if err:
                    raise err
            else:
                ENFORCER.enforce_call(action='identity:update_domain_role',
                                      member_target_type='role',
                                      member_target=role)
        request_body_role = self.request_body_json.get('role', {})
        validation.lazy_validate(schema.role_update, request_body_role)
        self._require_matching_id(request_body_role)
        ref = PROVIDERS.role_api.update_role(
            role_id, request_body_role, initiator=self.audit_initiator)
        return self.wrap_member(ref)

    def delete(self, role_id):
        """Delete role.

        DELETE /v3/roles/{role_id}
        """
        err = None
        role = {}
        try:
            role = PROVIDERS.role_api.get_role(role_id)
        except Exception as e:  # nosec
            # We don't raise out here, we raise out after enforcement, this
            # ensures we do not leak role existence. Do nothing yet, process
            # enforcement before raising out an error.
            err = e
        finally:
            if err is not None or not self._is_domain_role(role):
                ENFORCER.enforce_call(action='identity:delete_role')
                if err:
                    raise err
            else:
                ENFORCER.enforce_call(action='identity:delete_domain_role',
                                      member_target_type='role',
                                      member_target=role)
        PROVIDERS.role_api.delete_role(role_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


def _build_enforcement_target_ref():
    ref = {}
    if flask.request.view_args:
        ref['prior_role'] = PROVIDERS.role_api.get_role(
            flask.request.view_args.get('prior_role_id'))
        if flask.request.view_args.get('implied_role_id'):
            ref['implied_role'] = PROVIDERS.role_api.get_role(
                flask.request.view_args['implied_role_id'])
    return ref


class RoleImplicationListResource(flask_restful.Resource):
    def get(self, prior_role_id):
        """List Implied Roles.

        GET/HEAD /v3/roles/{prior_role_id}/implies
        """
        ENFORCER.enforce_call(action='identity:list_implied_roles',
                              build_target=_build_enforcement_target_ref)
        ref = PROVIDERS.role_api.list_implied_roles(prior_role_id)
        implied_ids = [r['implied_role_id'] for r in ref]
        response_json = shared.role_inference_response(prior_role_id)
        response_json['role_inference']['implies'] = []
        for implied_id in implied_ids:
            implied_role = PROVIDERS.role_api.get_role(implied_id)
            response_json['role_inference']['implies'].append(
                shared.build_implied_role_response_data(implied_role))
        response_json['links'] = {
            'self': ks_flask.base_url(
                path='/roles/%s/implies' % prior_role_id)}
        return response_json


class RoleImplicationResource(flask_restful.Resource):

    def head(self, prior_role_id, implied_role_id=None):
        # TODO(morgan): deprecate "check_implied_role" policy, as a user must
        # have both check_implied_role and get_implied_role to use the head
        # action. This enforcement of HEAD is historical for
        # consistent policy enforcement behavior even if it is superfluous.
        # Alternatively we can keep check_implied_role and reference
        # ._get_implied_role instead.
        ENFORCER.enforce_call(action='identity:check_implied_role',
                              build_target=_build_enforcement_target_ref)
        self.get(prior_role_id, implied_role_id)
        # NOTE(morgan): Our API here breaks HTTP Spec. This should be evaluated
        # for a future fix. This should just return the above "get" however,
        # we document and implment this as a NO_CONTENT response. NO_CONTENT
        # here is incorrect. It is maintained as is for API contract reasons.
        return None, http.client.NO_CONTENT

    def get(self, prior_role_id, implied_role_id):
        """Get implied role.

        GET/HEAD /v3/roles/{prior_role_id}/implies/{implied_role_id}
        """
        ENFORCER.enforce_call(
            action='identity:get_implied_role',
            build_target=_build_enforcement_target_ref)
        return self._get_implied_role(prior_role_id, implied_role_id)

    def _get_implied_role(self, prior_role_id, implied_role_id):
        # Isolate this logic so it can be re-used without added enforcement
        PROVIDERS.role_api.get_implied_role(
            prior_role_id, implied_role_id)
        implied_role_ref = PROVIDERS.role_api.get_role(implied_role_id)
        response_json = shared.role_inference_response(prior_role_id)
        response_json['role_inference'][
            'implies'] = shared.build_implied_role_response_data(
            implied_role_ref)
        response_json['links'] = {
            'self': ks_flask.base_url(
                path='/roles/%(prior)s/implies/%(implies)s' % {
                    'prior': prior_role_id, 'implies': implied_role_id})}
        return response_json

    def put(self, prior_role_id, implied_role_id):
        """Create implied role.

        PUT /v3/roles/{prior_role_id}/implies/{implied_role_id}
        """
        ENFORCER.enforce_call(action='identity:create_implied_role',
                              build_target=_build_enforcement_target_ref)
        PROVIDERS.role_api.create_implied_role(prior_role_id, implied_role_id)
        response_json = self._get_implied_role(prior_role_id, implied_role_id)
        return response_json, http.client.CREATED

    def delete(self, prior_role_id, implied_role_id):
        """Delete implied role.

        DELETE /v3/roles/{prior_role_id}/implies/{implied_role_id}
        """
        ENFORCER.enforce_call(action='identity:delete_implied_role',
                              build_target=_build_enforcement_target_ref)
        PROVIDERS.role_api.delete_implied_role(prior_role_id, implied_role_id)
        return None, http.client.NO_CONTENT


class RoleAPI(ks_flask.APIBase):
    _name = 'roles'
    _import_name = __name__
    resources = [RoleResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=RoleImplicationListResource,
            url='/roles/<string:prior_role_id>/implies',
            resource_kwargs={},
            rel='implied_roles',
            path_vars={'prior_role_id': json_home.Parameters.ROLE_ID}),
        ks_flask.construct_resource_map(
            resource=RoleImplicationResource,
            resource_kwargs={},
            url=('/roles/<string:prior_role_id>/'
                 'implies/<string:implied_role_id>'),
            rel='implied_role',
            path_vars={
                'prior_role_id': json_home.Parameters.ROLE_ID,
                'implied_role_id': json_home.Parameters.ROLE_ID})
    ]


APIs = (RoleAPI,)

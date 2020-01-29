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

# This file handles all flask-restful resources for /policy

import flask_restful
import http.client
from oslo_log import versionutils

from keystone.api._shared import json_home_relations
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
from keystone.policy import schema
from keystone.server import flask as ks_flask

ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs

_resource_rel_func = json_home_relations.os_endpoint_policy_resource_rel_func


class PolicyResource(ks_flask.ResourceBase):
    collection_key = 'policies'
    member_key = 'policy'

    def get(self, policy_id=None):
        if policy_id:
            return self._get_policy(policy_id)
        return self._list_policies()

    @versionutils.deprecated(
        as_of=versionutils.deprecated.QUEENS,
        what='identity:get_policy of the v3 Policy APIs'
    )
    def _get_policy(self, policy_id):
        ENFORCER.enforce_call(action='identity:get_policy')
        ref = PROVIDERS.policy_api.get_policy(policy_id)
        return self.wrap_member(ref)

    @versionutils.deprecated(
        as_of=versionutils.deprecated.QUEENS,
        what='identity:list_policies of the v3 Policy APIs'
    )
    def _list_policies(self):
        ENFORCER.enforce_call(action='identity:list_policies')
        filters = ['type']
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.policy_api.list_policies(hints=hints)
        return self.wrap_collection(refs, hints=hints)

    @versionutils.deprecated(
        as_of=versionutils.deprecated.QUEENS,
        what='identity:create_policy of the v3 Policy APIs'
    )
    def post(self):
        ENFORCER.enforce_call(action='identity:create_policy')
        policy_body = self.request_body_json.get('policy', {})
        validation.lazy_validate(schema.policy_create, policy_body)
        policy = self._assign_unique_id(self._normalize_dict(policy_body))

        ref = PROVIDERS.policy_api.create_policy(
            policy['id'], policy, initiator=self.audit_initiator
        )
        return self.wrap_member(ref), http.client.CREATED

    @versionutils.deprecated(
        as_of=versionutils.deprecated.QUEENS,
        what='identity:update_policy of the v3 Policy APIs'
    )
    def patch(self, policy_id):
        ENFORCER.enforce_call(action='identity:update_policy')
        policy_body = self.request_body_json.get('policy', {})
        validation.lazy_validate(schema.policy_update, policy_body)

        ref = PROVIDERS.policy_api.update_policy(
            policy_id, policy_body, initiator=self.audit_initiator
        )
        return self.wrap_member(ref)

    @versionutils.deprecated(
        as_of=versionutils.deprecated.QUEENS,
        what='identity:delete_policy of the v3 Policy APIs'
    )
    def delete(self, policy_id):
        ENFORCER.enforce_call(action='identity:delete_policy')
        res = PROVIDERS.policy_api.delete_policy(
            policy_id, initiator=self.audit_initiator
        )
        return (res, http.client.NO_CONTENT)


class EndpointPolicyResource(flask_restful.Resource):

    def get(self, policy_id):
        ENFORCER.enforce_call(action='identity:list_endpoints_for_policy')
        PROVIDERS.policy_api.get_policy(policy_id)
        endpoints = PROVIDERS.endpoint_policy_api.list_endpoints_for_policy(
            policy_id
        )
        self._remove_legacy_ids(endpoints)
        return ks_flask.ResourceBase.wrap_collection(
            endpoints, collection_name='endpoints'
        )

    def _remove_legacy_ids(self, endpoints):
        for endpoint in endpoints:
            endpoint.pop('legacy_endpoint_id', None)


class EndpointPolicyAssociations(flask_restful.Resource):

    def get(self, policy_id, endpoint_id):
        action = 'identity:check_policy_association_for_endpoint'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.endpoint_policy_api.check_policy_association(
            policy_id, endpoint_id=endpoint_id
        )
        return None, http.client.NO_CONTENT

    def put(self, policy_id, endpoint_id):
        action = 'identity:create_policy_association_for_endpoint'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy_id, endpoint_id=endpoint_id
        )
        return None, http.client.NO_CONTENT

    def delete(self, policy_id, endpoint_id):
        action = 'identity:delete_policy_association_for_endpoint'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_endpoint(endpoint_id)
        PROVIDERS.endpoint_policy_api.delete_policy_association(
            policy_id, endpoint_id=endpoint_id
        )
        return None, http.client.NO_CONTENT


class ServicePolicyAssociations(flask_restful.Resource):

    def get(self, policy_id, service_id):
        action = 'identity:check_policy_association_for_service'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_service(service_id)
        PROVIDERS.endpoint_policy_api.check_policy_association(
            policy_id, service_id=service_id
        )
        return None, http.client.NO_CONTENT

    def put(self, policy_id, service_id):
        action = 'identity:create_policy_association_for_service'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_service(service_id)
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy_id, service_id=service_id
        )
        return None, http.client.NO_CONTENT

    def delete(self, policy_id, service_id):
        action = 'identity:delete_policy_association_for_service'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_service(service_id)
        PROVIDERS.endpoint_policy_api.delete_policy_association(
            policy_id, service_id=service_id
        )
        return None, http.client.NO_CONTENT


class ServiceRegionPolicyAssociations(flask_restful.Resource):

    def get(self, policy_id, service_id, region_id):
        action = 'identity:check_policy_association_for_region_and_service'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_service(service_id)
        PROVIDERS.catalog_api.get_region(region_id)
        PROVIDERS.endpoint_policy_api.check_policy_association(
            policy_id, service_id=service_id, region_id=region_id
        )
        return None, http.client.NO_CONTENT

    def put(self, policy_id, service_id, region_id):
        action = 'identity:create_policy_association_for_region_and_service'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_service(service_id)
        PROVIDERS.catalog_api.get_region(region_id)
        PROVIDERS.endpoint_policy_api.create_policy_association(
            policy_id, service_id=service_id, region_id=region_id
        )
        return None, http.client.NO_CONTENT

    def delete(self, policy_id, service_id, region_id):
        action = 'identity:delete_policy_association_for_region_and_service'
        ENFORCER.enforce_call(action=action)
        PROVIDERS.policy_api.get_policy(policy_id)
        PROVIDERS.catalog_api.get_service(service_id)
        PROVIDERS.catalog_api.get_region(region_id)
        PROVIDERS.endpoint_policy_api.delete_policy_association(
            policy_id, service_id=service_id, region_id=region_id
        )
        return None, http.client.NO_CONTENT


class PolicyAPI(ks_flask.APIBase):
    _name = 'policy'
    _import_name = __name__
    resources = [PolicyResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=EndpointPolicyResource,
            url='/policies/<string:policy_id>/OS-ENDPOINT-POLICY/endpoints',
            resource_kwargs={},
            rel='policy_endpoints',
            path_vars={'policy_id': json_home.Parameters.POLICY_ID},
            resource_relation_func=_resource_rel_func
        ),
        ks_flask.construct_resource_map(
            resource=EndpointPolicyAssociations,
            url=('/policies/<string:policy_id>/OS-ENDPOINT-POLICY/'
                 'endpoints/<string:endpoint_id>'),
            resource_kwargs={},
            rel='endpoint_policy_association',
            path_vars={
                'policy_id': json_home.Parameters.POLICY_ID,
                'endpoint_id': json_home.Parameters.ENDPOINT_ID
            },
            resource_relation_func=_resource_rel_func
        ),
        ks_flask.construct_resource_map(
            resource=ServicePolicyAssociations,
            url=('/policies/<string:policy_id>/OS-ENDPOINT-POLICY/'
                 'services/<string:service_id>'),
            resource_kwargs={},
            rel='service_policy_association',
            path_vars={
                'policy_id': json_home.Parameters.POLICY_ID,
                'service_id': json_home.Parameters.SERVICE_ID
            },
            resource_relation_func=_resource_rel_func
        ),
        ks_flask.construct_resource_map(
            resource=ServiceRegionPolicyAssociations,
            url=('/policies/<string:policy_id>/OS-ENDPOINT-POLICY/'
                 'services/<string:service_id>/regions/<string:region_id>'),
            resource_kwargs={},
            rel='region_and_service_policy_association',
            path_vars={
                'policy_id': json_home.Parameters.POLICY_ID,
                'service_id': json_home.Parameters.SERVICE_ID,
                'region_id': json_home.Parameters.REGION_ID
            },
            resource_relation_func=_resource_rel_func
        )
    ]


APIs = (PolicyAPI,)

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

# This file handles all flask-restful resources for /v3/OS-FEDERATION

import flask
import flask_restful
import http.client
from oslo_serialization import jsonutils

from keystone.api._shared import authentication
from keystone.api._shared import json_home_relations
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import render_token
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.federation import schema
from keystone.federation import utils
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs


_build_param_relation = json_home_relations.os_federation_parameter_rel_func
_build_resource_relation = json_home_relations.os_federation_resource_rel_func

IDP_ID_PARAMETER_RELATION = _build_param_relation(parameter_name='idp_id')
PROTOCOL_ID_PARAMETER_RELATION = _build_param_relation(
    parameter_name='protocol_id')
SP_ID_PARAMETER_RELATION = _build_param_relation(parameter_name='sp_id')


def _combine_lists_uniquely(a, b):
    # it's most likely that only one of these will be filled so avoid
    # the combination if possible.
    if a and b:
        return {x['id']: x for x in a + b}.values()
    else:
        return a or b


class _ResourceBase(ks_flask.ResourceBase):
    json_home_resource_rel_func = _build_resource_relation
    json_home_parameter_rel_func = _build_param_relation

    @classmethod
    def wrap_member(cls, ref, collection_name=None, member_name=None):
        cls._add_self_referential_link(ref, collection_name)
        cls._add_related_links(ref)
        return {member_name or cls.member_key: cls.filter_params(ref)}

    @staticmethod
    def _add_related_links(ref):
        # Do Nothing, This is in support of child class mechanisms.
        pass


class IdentityProvidersResource(_ResourceBase):
    collection_key = 'identity_providers'
    member_key = 'identity_provider'
    api_prefix = '/OS-FEDERATION'
    _public_parameters = frozenset(['id', 'enabled', 'description',
                                    'remote_ids', 'links', 'domain_id',
                                    'authorization_ttl'
                                    ])
    _id_path_param_name_override = 'idp_id'

    @staticmethod
    def _add_related_links(ref):
        """Add URLs for entities related with Identity Provider.

        Add URLs pointing to:
        - protocols tied to the Identity Provider

        """
        base_path = ref['links'].get('self')
        if base_path is None:
            base_path = '/'.join(ks_flask.base_url(path='/%s' % ref['id']))

        for name in ['protocols']:
            ref['links'][name] = '/'.join([base_path, name])

    def get(self, idp_id=None):
        if idp_id is not None:
            return self._get_idp(idp_id)
        return self._list_idps()

    def _get_idp(self, idp_id):
        """Get an IDP resource.

        GET/HEAD /OS-FEDERATION/identity_providers/{idp_id}
        """
        ENFORCER.enforce_call(action='identity:get_identity_provider')
        ref = PROVIDERS.federation_api.get_idp(idp_id)
        return self.wrap_member(ref)

    def _list_idps(self):
        """List all identity providers.

        GET/HEAD /OS-FEDERATION/identity_providers
        """
        filters = ['id', 'enabled']
        ENFORCER.enforce_call(action='identity:list_identity_providers',
                              filters=filters)
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.federation_api.list_idps(hints=hints)
        refs = [self.filter_params(r) for r in refs]
        collection = self.wrap_collection(refs, hints=hints)
        for r in collection[self.collection_key]:
            # Add the related links explicitly
            self._add_related_links(r)
        return collection

    def put(self, idp_id):
        """Create an idp resource for federated authentication.

        PUT /OS-FEDERATION/identity_providers/{idp_id}
        """
        ENFORCER.enforce_call(action='identity:create_identity_provider')
        idp = self.request_body_json.get('identity_provider', {})
        validation.lazy_validate(schema.identity_provider_create,
                                 idp)
        idp = self._normalize_dict(idp)
        idp.setdefault('enabled', False)
        idp_ref = PROVIDERS.federation_api.create_idp(
            idp_id, idp)
        return self.wrap_member(idp_ref), http.client.CREATED

    def patch(self, idp_id):
        ENFORCER.enforce_call(action='identity:update_identity_provider')
        idp = self.request_body_json.get('identity_provider', {})
        validation.lazy_validate(schema.identity_provider_update, idp)
        idp = self._normalize_dict(idp)
        idp_ref = PROVIDERS.federation_api.update_idp(
            idp_id, idp)
        return self.wrap_member(idp_ref)

    def delete(self, idp_id):
        ENFORCER.enforce_call(action='identity:delete_identity_provider')
        PROVIDERS.federation_api.delete_idp(idp_id)
        return None, http.client.NO_CONTENT


class _IdentityProvidersProtocolsResourceBase(_ResourceBase):
    collection_key = 'protocols'
    member_key = 'protocol'
    _public_parameters = frozenset(['id', 'mapping_id', 'links'])
    json_home_additional_parameters = {
        'idp_id': IDP_ID_PARAMETER_RELATION}
    json_home_collection_resource_name_override = 'identity_provider_protocols'
    json_home_member_resource_name_override = 'identity_provider_protocol'

    @staticmethod
    def _add_related_links(ref):
        """Add new entries to the 'links' subdictionary in the response.

        Adds 'identity_provider' key with URL pointing to related identity
        provider as a value.

        :param ref: response dictionary

        """
        ref.setdefault('links', {})
        ref['links']['identity_provider'] = ks_flask.base_url(
            path=ref['idp_id'])


class IDPProtocolsListResource(_IdentityProvidersProtocolsResourceBase):

    def get(self, idp_id):
        """List protocols for an IDP.

        HEAD/GET /OS-FEDERATION/identity_providers/{idp_id}/protocols
        """
        ENFORCER.enforce_call(action='identity:list_protocols')
        protocol_refs = PROVIDERS.federation_api.list_protocols(idp_id)
        protocols = list(protocol_refs)
        collection = self.wrap_collection(protocols)
        for r in collection[self.collection_key]:
            # explicitly add related links
            self._add_related_links(r)
        return collection


class IDPProtocolsCRUDResource(_IdentityProvidersProtocolsResourceBase):

    def get(self, idp_id, protocol_id):
        """Get protocols for an IDP.

        HEAD/GET /OS-FEDERATION/identity_providers/
                 {idp_id}/protocols/{protocol_id}
        """
        ENFORCER.enforce_call(action='identity:get_protocol')
        ref = PROVIDERS.federation_api.get_protocol(idp_id, protocol_id)
        return self.wrap_member(ref)

    def put(self, idp_id, protocol_id):
        """Create protocol for an IDP.

        PUT /OS-Federation/identity_providers/{idp_id}/protocols/{protocol_id}
        """
        ENFORCER.enforce_call(action='identity:create_protocol')
        protocol = self.request_body_json.get('protocol', {})
        validation.lazy_validate(schema.protocol_create, protocol)
        protocol = self._normalize_dict(protocol)
        ref = PROVIDERS.federation_api.create_protocol(idp_id, protocol_id,
                                                       protocol)
        return self.wrap_member(ref), http.client.CREATED

    def patch(self, idp_id, protocol_id):
        """Update protocol for an IDP.

        PATCH /OS-FEDERATION/identity_providers/
              {idp_id}/protocols/{protocol_id}
        """
        ENFORCER.enforce_call(action='identity:update_protocol')
        protocol = self.request_body_json.get('protocol', {})
        validation.lazy_validate(schema.protocol_update, protocol)
        ref = PROVIDERS.federation_api.update_protocol(idp_id, protocol_id,
                                                       protocol)
        return self.wrap_member(ref)

    def delete(self, idp_id, protocol_id):
        """Delete a protocol from an IDP.

        DELETE /OS-FEDERATION/identity_providers/
               {idp_id}/protocols/{protocol_id}
        """
        ENFORCER.enforce_call(action='identity:delete_protocol')
        PROVIDERS.federation_api.delete_protocol(idp_id, protocol_id)
        return None, http.client.NO_CONTENT


class MappingResource(_ResourceBase):
    collection_key = 'mappings'
    member_key = 'mapping'
    api_prefix = '/OS-FEDERATION'

    def get(self, mapping_id=None):
        if mapping_id is not None:
            return self._get_mapping(mapping_id)
        return self._list_mappings()

    def _get_mapping(self, mapping_id):
        """Get a mapping.

        HEAD/GET /OS-FEDERATION/mappings/{mapping_id}
        """
        ENFORCER.enforce_call(action='identity:get_mapping')
        return self.wrap_member(PROVIDERS.federation_api.get_mapping(
            mapping_id))

    def _list_mappings(self):
        """List mappings.

        HEAD/GET /OS-FEDERATION/mappings
        """
        ENFORCER.enforce_call(action='identity:list_mappings')
        return self.wrap_collection(PROVIDERS.federation_api.list_mappings())

    def put(self, mapping_id):
        """Create a mapping.

        PUT /OS-FEDERATION/mappings/{mapping_id}
        """
        ENFORCER.enforce_call(action='identity:create_mapping')
        mapping = self.request_body_json.get('mapping', {})
        mapping = self._normalize_dict(mapping)
        utils.validate_mapping_structure(mapping)
        mapping_ref = PROVIDERS.federation_api.create_mapping(
            mapping_id, mapping)
        return self.wrap_member(mapping_ref), http.client.CREATED

    def patch(self, mapping_id):
        """Update a mapping.

        PATCH /OS-FEDERATION/mappings/{mapping_id}
        """
        ENFORCER.enforce_call(action='identity:update_mapping')
        mapping = self.request_body_json.get('mapping', {})
        mapping = self._normalize_dict(mapping)
        utils.validate_mapping_structure(mapping)
        mapping_ref = PROVIDERS.federation_api.update_mapping(
            mapping_id, mapping)
        return self.wrap_member(mapping_ref)

    def delete(self, mapping_id):
        """Delete a mapping.

        DELETE /OS-FEDERATION/mappings/{mapping_id}
        """
        ENFORCER.enforce_call(action='identity:delete_mapping')
        PROVIDERS.federation_api.delete_mapping(mapping_id)
        return None, http.client.NO_CONTENT


class ServiceProvidersResource(_ResourceBase):
    collection_key = 'service_providers'
    member_key = 'service_provider'
    _public_parameters = frozenset(['auth_url', 'id', 'enabled', 'description',
                                    'links', 'relay_state_prefix', 'sp_url'])
    _id_path_param_name_override = 'sp_id'
    api_prefix = '/OS-FEDERATION'

    def get(self, sp_id=None):
        if sp_id is not None:
            return self._get_service_provider(sp_id)
        return self._list_service_providers()

    def _get_service_provider(self, sp_id):
        """Get a service provider.

        GET/HEAD /OS-FEDERATION/service_providers/{sp_id}
        """
        ENFORCER.enforce_call(action='identity:get_service_provider')
        return self.wrap_member(PROVIDERS.federation_api.get_sp(sp_id))

    def _list_service_providers(self):
        """List service providers.

        GET/HEAD /OS-FEDERATION/service_providers
        """
        filters = ['id', 'enabled']
        ENFORCER.enforce_call(action='identity:list_service_providers',
                              filters=filters)
        hints = self.build_driver_hints(filters)
        refs = [self.filter_params(r)
                for r in
                PROVIDERS.federation_api.list_sps(hints=hints)]
        return self.wrap_collection(refs, hints=hints)

    def put(self, sp_id):
        """Create a service provider.

        PUT /OS-FEDERATION/service_providers/{sp_id}
        """
        ENFORCER.enforce_call(action='identity:create_service_provider')
        sp = self.request_body_json.get('service_provider', {})
        validation.lazy_validate(schema.service_provider_create, sp)
        sp = self._normalize_dict(sp)
        sp.setdefault('enabled', False)
        sp.setdefault('relay_state_prefix',
                      CONF.saml.relay_state_prefix)
        sp_ref = PROVIDERS.federation_api.create_sp(sp_id, sp)
        return self.wrap_member(sp_ref), http.client.CREATED

    def patch(self, sp_id):
        """Update a service provider.

        PATCH /OS-FEDERATION/service_providers/{sp_id}
        """
        ENFORCER.enforce_call(action='identity:update_service_provider')
        sp = self.request_body_json.get('service_provider', {})
        validation.lazy_validate(schema.service_provider_update, sp)
        sp = self._normalize_dict(sp)
        sp_ref = PROVIDERS.federation_api.update_sp(sp_id, sp)
        return self.wrap_member(sp_ref)

    def delete(self, sp_id):
        """Delete a service provider.

        DELETE /OS-FEDERATION/service_providers/{sp_id}
        """
        ENFORCER.enforce_call(action='identity:delete_service_provider')
        PROVIDERS.federation_api.delete_sp(sp_id)
        return None, http.client.NO_CONTENT


class SAML2MetadataResource(flask_restful.Resource):
    @ks_flask.unenforced_api
    def get(self):
        """Get SAML2 metadata.

        GET/HEAD /OS-FEDERATION/saml2/metadata
        """
        metadata_path = CONF.saml.idp_metadata_path
        try:
            with open(metadata_path, 'r') as metadata_handler:
                metadata = metadata_handler.read()
        except IOError as e:
            # Raise HTTP 500 in case Metadata file cannot be read.
            raise exception.MetadataFileError(reason=e)
        resp = flask.make_response(metadata, http.client.OK)
        resp.headers['Content-Type'] = 'text/xml'
        return resp


class OSFederationAuthResource(flask_restful.Resource):

    @ks_flask.unenforced_api
    def get(self, idp_id, protocol_id):
        """Authenticate from dedicated uri endpoint.

        GET/HEAD /OS-FEDERATION/identity_providers/
                 {idp_id}/protocols/{protocol_id}/auth
        """
        return self._auth(idp_id, protocol_id)

    @ks_flask.unenforced_api
    def post(self, idp_id, protocol_id):
        """Authenticate from dedicated uri endpoint.

        POST /OS-FEDERATION/identity_providers/
             {idp_id}/protocols/{protocol_id}/auth
        """
        return self._auth(idp_id, protocol_id)

    def _auth(self, idp_id, protocol_id):
        """Build and pass auth data to authentication code.

        Build HTTP request body for federated authentication and inject
        it into the ``authenticate_for_token`` function.
        """
        auth = {
            'identity': {
                'methods': [protocol_id],
                protocol_id: {
                    'identity_provider': idp_id,
                    'protocol': protocol_id
                },
            }
        }
        token = authentication.authenticate_for_token(auth)
        token_data = render_token.render_token_response_from_model(token)
        resp_data = jsonutils.dumps(token_data)
        flask_resp = flask.make_response(resp_data, http.client.CREATED)
        flask_resp.headers['X-Subject-Token'] = token.id
        flask_resp.headers['Content-Type'] = 'application/json'
        return flask_resp


class OSFederationAPI(ks_flask.APIBase):
    _name = 'OS-FEDERATION'
    _import_name = __name__
    _api_url_prefix = '/OS-FEDERATION'
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=SAML2MetadataResource,
            url='/saml2/metadata',
            resource_kwargs={},
            rel='metadata',
            resource_relation_func=_build_resource_relation),
        ks_flask.construct_resource_map(
            resource=OSFederationAuthResource,
            url=('/identity_providers/<string:idp_id>/protocols/'
                 '<string:protocol_id>/auth'),
            resource_kwargs={},
            rel='identity_provider_protocol_auth',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION,
                'protocol_id': PROTOCOL_ID_PARAMETER_RELATION}),
    ]


class OSFederationIdentityProvidersAPI(ks_flask.APIBase):
    _name = 'identity_providers'
    _import_name = __name__
    _api_url_prefix = '/OS-FEDERATION'
    resources = [IdentityProvidersResource]
    resource_mapping = []


class OSFederationIdentityProvidersProtocolsAPI(ks_flask.APIBase):
    _name = 'protocols'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=IDPProtocolsCRUDResource,
            url=('/OS-FEDERATION/identity_providers/<string:idp_id>/protocols/'
                 '<string:protocol_id>'),
            resource_kwargs={},
            rel='identity_provider_protocol',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION,
                'protocol_id': PROTOCOL_ID_PARAMETER_RELATION
            }
        ),
        ks_flask.construct_resource_map(
            resource=IDPProtocolsListResource,
            url='/OS-FEDERATION/identity_providers/<string:idp_id>/protocols',
            resource_kwargs={},
            rel='identity_provider_protocols',
            resource_relation_func=_build_resource_relation,
            path_vars={
                'idp_id': IDP_ID_PARAMETER_RELATION
            }
        ),
    ]


class OSFederationMappingsAPI(ks_flask.APIBase):
    _name = 'mappings'
    _import_name = __name__
    _api_url_prefix = '/OS-FEDERATION'
    resources = [MappingResource]
    resource_mapping = []


class OSFederationServiceProvidersAPI(ks_flask.APIBase):
    _name = 'service_providers'
    _import_name = __name__
    _api_url_prefix = '/OS-FEDERATION'
    resources = [ServiceProvidersResource]
    resource_mapping = []


APIs = (
    OSFederationAPI,
    OSFederationIdentityProvidersAPI,
    OSFederationIdentityProvidersProtocolsAPI,
    OSFederationMappingsAPI,
    OSFederationServiceProvidersAPI
)

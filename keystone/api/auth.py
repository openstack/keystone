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

# This file handles all flask-restful resources for /v3/auth
import string

import flask
import flask_restful
import http.client
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import strutils
import urllib
import werkzeug.exceptions

from keystone.api._shared import authentication
from keystone.api._shared import json_home_relations
from keystone.api._shared import saml
from keystone.auth import schema as auth_schema
from keystone.common import authorization
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import render_token
from keystone.common import utils as k_utils
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.federation import idp as keystone_idp
from keystone.federation import schema as federation_schema
from keystone.federation import utils as federation_utils
from keystone.i18n import _
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


def _combine_lists_uniquely(a, b):
    # it's most likely that only one of these will be filled so avoid
    # the combination if possible.
    if a and b:
        return {x['id']: x for x in a + b}.values()
    else:
        return a or b


def _build_response_headers(service_provider):
    # URLs in header are encoded into bytes
    return [('Content-Type', 'text/xml'),
            ('X-sp-url', service_provider['sp_url'].encode('utf-8')),
            ('X-auth-url', service_provider['auth_url'].encode('utf-8'))]


def _get_sso_origin_host():
    """Validate and return originating dashboard URL.

    Make sure the parameter is specified in the request's URL as well its
    value belongs to a list of trusted dashboards.

    :raises keystone.exception.ValidationError: ``origin`` query parameter
        was not specified. The URL is deemed invalid.
    :raises keystone.exception.Unauthorized: URL specified in origin query
        parameter does not exist in list of websso trusted dashboards.
    :returns: URL with the originating dashboard

    """
    origin = flask.request.args.get('origin')

    if not origin:
        msg = 'Request must have an origin query parameter'
        tr_msg = _('Request must have an origin query parameter')
        LOG.error(msg)
        raise exception.ValidationError(tr_msg)

    host = urllib.parse.unquote_plus(origin)

    # change trusted_dashboard hostnames to lowercase before comparison
    trusted_dashboards = [k_utils.lower_case_hostname(trusted)
                          for trusted in CONF.federation.trusted_dashboard]

    if host not in trusted_dashboards:
        msg = '%(host)s is not a trusted dashboard host' % {'host': host}
        tr_msg = _('%(host)s is not a trusted dashboard host') % {
            'host': host}
        LOG.error(msg)
        raise exception.Unauthorized(tr_msg)

    return host


class _AuthFederationWebSSOBase(ks_flask.ResourceBase):
    @staticmethod
    def _render_template_response(host, token_id):
        with open(CONF.federation.sso_callback_template) as template:
            src = string.Template(template.read())
        subs = {'host': host, 'token': token_id}
        body = src.substitute(subs)
        resp = flask.make_response(body, http.client.OK)
        resp.charset = 'utf-8'
        resp.headers['Content-Type'] = 'text/html'
        return resp


class AuthProjectsResource(ks_flask.ResourceBase):
    collection_key = 'projects'
    member_key = 'project'

    def get(self):
        """Get possible project scopes for token.

        GET/HEAD /v3/auth/projects
        GET/HEAD /v3/OS-FEDERATION/projects
        """
        ENFORCER.enforce_call(action='identity:get_auth_projects')
        user_id = self.auth_context.get('user_id')
        group_ids = self.auth_context.get('group_ids')

        user_p_refs = []
        grp_p_refs = []

        if user_id:
            try:
                user_p_refs = PROVIDERS.assignment_api.list_projects_for_user(
                    user_id)
            except exception.UserNotFound:  # nosec
                # federated users have an id but they don't link to anything
                pass

        if group_ids:
            grp_p_refs = PROVIDERS.assignment_api.list_projects_for_groups(
                group_ids)
        refs = _combine_lists_uniquely(user_p_refs, grp_p_refs)
        return self.wrap_collection(refs)


class AuthDomainsResource(ks_flask.ResourceBase):
    collection_key = 'domains'
    member_key = 'domain'

    def get(self):
        """Get possible domain scopes for token.

        GET/HEAD /v3/auth/domains
        GET/HEAD /v3/OS-FEDERATION/domains
        """
        ENFORCER.enforce_call(action='identity:get_auth_domains')
        user_id = self.auth_context.get('user_id')
        group_ids = self.auth_context.get('group_ids')

        user_d_refs = []
        grp_d_refs = []

        if user_id:
            try:
                user_d_refs = PROVIDERS.assignment_api.list_domains_for_user(
                    user_id)
            except exception.UserNotFound:  # nosec
                # federated users have an id but they don't link to anything
                pass

        if group_ids:
            grp_d_refs = PROVIDERS.assignment_api.list_domains_for_groups(
                group_ids)

        refs = _combine_lists_uniquely(user_d_refs, grp_d_refs)
        return self.wrap_collection(refs)


class AuthSystemResource(_AuthFederationWebSSOBase):
    def get(self):
        """Get possible system scopes for token.

        GET/HEAD /v3/auth/system
        """
        ENFORCER.enforce_call(action='identity:get_auth_system')
        user_id = self.auth_context.get('user_id')
        group_ids = self.auth_context.get('group_ids')

        user_assignments = []
        group_assignments = []

        if user_id:
            try:
                user_assignments = (
                    PROVIDERS.assignment_api.list_system_grants_for_user(
                        user_id)
                )
            except exception.UserNotFound:  # nosec
                # federated users have an id but they don't link to anything
                pass

        if group_ids:
            group_assignments = (
                PROVIDERS.assignment_api.list_system_grants_for_groups(
                    group_ids)
            )

        assignments = _combine_lists_uniquely(
            user_assignments, group_assignments)

        if assignments:
            response = {
                'system': [{'all': True}],
                'links': {
                    'self': ks_flask.base_url(path='auth/system')
                }
            }
        else:
            response = {
                'system': [],
                'links': {
                    'self': ks_flask.base_url(path='auth/system')
                }
            }
        return response


class AuthCatalogResource(_AuthFederationWebSSOBase):
    def get(self):
        """Get service catalog for token.

        GET/HEAD /v3/auth/catalog
        """
        ENFORCER.enforce_call(action='identity:get_auth_catalog')
        user_id = self.auth_context.get('user_id')
        project_id = self.auth_context.get('project_id')

        if not project_id:
            raise exception.Forbidden(
                _('A project-scoped token is required to produce a '
                  'service catalog.'))

        return {
            'catalog': PROVIDERS.catalog_api.get_v3_catalog(
                user_id, project_id
            ),
            'links': {
                'self': ks_flask.base_url(path='auth/catalog')
            }
        }


class AuthTokenOSPKIResource(flask_restful.Resource):
    @ks_flask.unenforced_api
    def get(self):
        """Deprecated; get revoked token list.

        GET/HEAD /v3/auth/tokens/OS-PKI/revoked
        """
        if not CONF.token.revoke_by_id:
            raise exception.Gone()
        # NOTE(lbragstad): This API is deprecated and isn't supported. Keystone
        # also doesn't store tokens, so returning a list of revoked tokens
        # would require keystone to write invalid tokens to disk, which defeats
        # the purpose. Return a 403 instead of removing the API altogether.
        raise exception.Forbidden()


class AuthTokenResource(_AuthFederationWebSSOBase):
    def get(self):
        """Validate a token.

        HEAD/GET /v3/auth/tokens
        """
        # TODO(morgan): eliminate the check_token action only use validate
        # NOTE(morgan): Well lookie here, we have different enforcements
        # for no good reason (historical), because the methods previously
        # had to be named different names. Check which method and do the
        # correct enforcement.
        if flask.request.method == 'HEAD':
            ENFORCER.enforce_call(action='identity:check_token')
        else:
            ENFORCER.enforce_call(action='identity:validate_token')

        token_id = flask.request.headers.get(
            authorization.SUBJECT_TOKEN_HEADER)
        access_rules_support = flask.request.headers.get(
            authorization.ACCESS_RULES_HEADER)
        allow_expired = strutils.bool_from_string(
            flask.request.args.get('allow_expired'))
        window_secs = CONF.token.allow_expired_window if allow_expired else 0
        include_catalog = 'nocatalog' not in flask.request.args
        token = PROVIDERS.token_provider_api.validate_token(
            token_id, window_seconds=window_secs,
            access_rules_support=access_rules_support)
        token_resp = render_token.render_token_response_from_model(
            token, include_catalog=include_catalog)
        resp_body = jsonutils.dumps(token_resp)
        response = flask.make_response(resp_body, http.client.OK)
        response.headers['X-Subject-Token'] = token_id
        response.headers['Content-Type'] = 'application/json'
        return response

    @ks_flask.unenforced_api
    def post(self):
        """Issue a token.

        POST /v3/auth/tokens
        """
        include_catalog = 'nocatalog' not in flask.request.args
        auth_data = self.request_body_json.get('auth')
        auth_schema.validate_issue_token_auth(auth_data)
        token = authentication.authenticate_for_token(auth_data)
        resp_data = render_token.render_token_response_from_model(
            token, include_catalog=include_catalog
        )
        resp_body = jsonutils.dumps(resp_data)
        response = flask.make_response(resp_body, http.client.CREATED)
        response.headers['X-Subject-Token'] = token.id
        response.headers['Content-Type'] = 'application/json'
        return response

    def delete(self):
        """Revoke a token.

        DELETE /v3/auth/tokens
        """
        ENFORCER.enforce_call(action='identity:revoke_token')
        token_id = flask.request.headers.get(
            authorization.SUBJECT_TOKEN_HEADER)
        PROVIDERS.token_provider_api.revoke_token(token_id)
        return None, http.client.NO_CONTENT


class AuthFederationWebSSOResource(_AuthFederationWebSSOBase):
    @classmethod
    def _perform_auth(cls, protocol_id):
        idps = PROVIDERS.federation_api.list_idps()
        remote_id = None
        for idp in idps:
            try:
                remote_id_name = federation_utils.get_remote_id_parameter(
                    idp, protocol_id)
            except exception.FederatedProtocolNotFound:
                # no protocol for this IdP, so this can't be the IdP we're
                # looking for
                continue
            remote_id = flask.request.environ.get(remote_id_name)
            if remote_id:
                break
        if not remote_id:
            msg = 'Missing entity ID from environment'
            tr_msg = _('Missing entity ID from environment')
            LOG.error(msg)
            raise exception.Unauthorized(tr_msg)

        host = _get_sso_origin_host()
        ref = PROVIDERS.federation_api.get_idp_from_remote_id(remote_id)
        identity_provider = ref['idp_id']
        token = authentication.federated_authenticate_for_token(
            identity_provider=identity_provider, protocol_id=protocol_id)
        return cls._render_template_response(host, token.id)

    @ks_flask.unenforced_api
    def get(self, protocol_id):
        return self._perform_auth(protocol_id)

    @ks_flask.unenforced_api
    def post(self, protocol_id):
        return self._perform_auth(protocol_id)


class AuthFederationWebSSOIDPsResource(_AuthFederationWebSSOBase):
    @classmethod
    def _perform_auth(cls, idp_id, protocol_id):
        host = _get_sso_origin_host()

        token = authentication.federated_authenticate_for_token(
            identity_provider=idp_id, protocol_id=protocol_id)
        return cls._render_template_response(host, token.id)

    @ks_flask.unenforced_api
    def get(self, idp_id, protocol_id):
        return self._perform_auth(idp_id, protocol_id)

    @ks_flask.unenforced_api
    def post(self, idp_id, protocol_id):
        return self._perform_auth(idp_id, protocol_id)


class AuthFederationSaml2Resource(_AuthFederationWebSSOBase):
    def get(self):
        raise werkzeug.exceptions.MethodNotAllowed(valid_methods=['POST'])

    @ks_flask.unenforced_api
    def post(self):
        """Exchange a scoped token for a SAML assertion.

        POST /v3/auth/OS-FEDERATION/saml2
        """
        auth = self.request_body_json.get('auth')
        validation.lazy_validate(federation_schema.saml_create, auth)
        response, service_provider = saml.create_base_saml_assertion(auth)
        headers = _build_response_headers(service_provider)
        response = flask.make_response(response.to_string(), http.client.OK)
        for header, value in headers:
            response.headers[header] = value
        return response


class AuthFederationSaml2ECPResource(_AuthFederationWebSSOBase):
    def get(self):
        raise werkzeug.exceptions.MethodNotAllowed(valid_methods=['POST'])

    @ks_flask.unenforced_api
    def post(self):
        """Exchange a scoped token for an ECP assertion.

        POST /v3/auth/OS-FEDERATION/saml2/ecp
        """
        auth = self.request_body_json.get('auth')
        validation.lazy_validate(federation_schema.saml_create, auth)
        saml_assertion, service_provider = saml.create_base_saml_assertion(
            auth)
        relay_state_prefix = service_provider['relay_state_prefix']

        generator = keystone_idp.ECPGenerator()
        ecp_assertion = generator.generate_ecp(
            saml_assertion, relay_state_prefix)
        headers = _build_response_headers(service_provider)
        response = flask.make_response(
            ecp_assertion.to_string(), http.client.OK)
        for header, value in headers:
            response.headers[header] = value
        return response


class AuthAPI(ks_flask.APIBase):
    _name = 'auth'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=AuthProjectsResource,
            url='/auth/projects',
            alternate_urls=[dict(
                url='/OS-FEDERATION/projects',
                json_home=ks_flask.construct_json_home_data(
                    rel='projects',
                    resource_relation_func=(
                        json_home_relations.os_federation_resource_rel_func)
                )
            )],

            rel='auth_projects',
            resource_kwargs={}
        ),
        ks_flask.construct_resource_map(
            resource=AuthDomainsResource,
            url='/auth/domains',
            alternate_urls=[dict(
                url='/OS-FEDERATION/domains',
                json_home=ks_flask.construct_json_home_data(
                    rel='domains',
                    resource_relation_func=(
                        json_home_relations.os_federation_resource_rel_func)
                )
            )],
            rel='auth_domains',
            resource_kwargs={},
        ),
        ks_flask.construct_resource_map(
            resource=AuthSystemResource,
            url='/auth/system',
            resource_kwargs={},
            rel='auth_system'
        ),
        ks_flask.construct_resource_map(
            resource=AuthCatalogResource,
            url='/auth/catalog',
            resource_kwargs={},
            rel='auth_catalog'
        ),
        ks_flask.construct_resource_map(
            resource=AuthTokenOSPKIResource,
            url='/auth/tokens/OS-PKI/revoked',
            resource_kwargs={},
            rel='revocations',
            resource_relation_func=json_home_relations.os_pki_resource_rel_func
        ),
        ks_flask.construct_resource_map(
            resource=AuthTokenResource,
            url='/auth/tokens',
            resource_kwargs={},
            rel='auth_tokens'
        )
    ]


class AuthFederationAPI(ks_flask.APIBase):
    _name = 'auth/OS-FEDERATION'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=AuthFederationSaml2Resource,
            url='/auth/OS-FEDERATION/saml2',
            resource_kwargs={},
            resource_relation_func=(
                json_home_relations.os_federation_resource_rel_func),
            rel='saml2'
        ),
        ks_flask.construct_resource_map(
            resource=AuthFederationSaml2ECPResource,
            url='/auth/OS-FEDERATION/saml2/ecp',
            resource_kwargs={},
            resource_relation_func=(
                json_home_relations.os_federation_resource_rel_func),
            rel='ecp'
        ),
        ks_flask.construct_resource_map(
            resource=AuthFederationWebSSOResource,
            url='/auth/OS-FEDERATION/websso/<string:protocol_id>',
            resource_kwargs={},
            rel='websso',
            resource_relation_func=(
                json_home_relations.os_federation_resource_rel_func),
            path_vars={
                'protocol_id': (
                    json_home_relations.os_federation_parameter_rel_func(
                        parameter_name='protocol_id'))}
        ),
        ks_flask.construct_resource_map(
            resource=AuthFederationWebSSOIDPsResource,
            url=('/auth/OS-FEDERATION/identity_providers/<string:idp_id>/'
                 'protocols/<string:protocol_id>/websso'),
            resource_kwargs={},
            rel='identity_providers_websso',
            resource_relation_func=(
                json_home_relations.os_federation_resource_rel_func),
            path_vars={
                'idp_id': (
                    json_home_relations.os_federation_parameter_rel_func(
                        parameter_name='idp_id')),
                'protocol_id': (
                    json_home_relations.os_federation_parameter_rel_func(
                        parameter_name='protocol_id'))}
        )
    ]


APIs = (
    AuthAPI,
    AuthFederationAPI,
)

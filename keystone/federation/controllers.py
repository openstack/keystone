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

"""Workflow logic for the Federation service."""

import string

from oslo_log import log
from six.moves import http_client
from six.moves import urllib
import webob

from keystone.auth import controllers as auth_controllers
from keystone.common import controller
from keystone.common import provider_api
from keystone.common import utils as k_utils
from keystone.common import validation
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.federation import idp as keystone_idp
from keystone.federation import schema
from keystone.federation import utils
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class _ControllerBase(controller.V3Controller):
    """Base behaviors for federation controllers."""

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""
        path = '/OS-FEDERATION/' + cls.collection_name
        return super(_ControllerBase, cls).base_url(context, path=path)


class Auth(auth_controllers.Auth):

    def _get_sso_origin_host(self, request):
        """Validate and return originating dashboard URL.

        Make sure the parameter is specified in the request's URL as well its
        value belongs to a list of trusted dashboards.

        :param context: request's context
        :raises keystone.exception.ValidationError: ``origin`` query parameter
            was not specified. The URL is deemed invalid.
        :raises keystone.exception.Unauthorized: URL specified in origin query
            parameter does not exist in list of websso trusted dashboards.
        :returns: URL with the originating dashboard

        """
        origin = request.params.get('origin')

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

    def federated_authentication(self, request, idp_id, protocol_id):
        """Authenticate from dedicated url endpoint.

        Build HTTP request body for federated authentication and inject
        it into the ``authenticate_for_token`` function.

        """
        auth = {
            'identity': {
                'methods': [protocol_id],
                protocol_id: {
                    'identity_provider': idp_id,
                    'protocol': protocol_id
                }
            }
        }

        return self.authenticate_for_token(request, auth=auth)

    def federated_sso_auth(self, request, protocol_id):
        try:
            remote_id_name = utils.get_remote_id_parameter(protocol_id)
            remote_id = request.environ[remote_id_name]
        except KeyError:
            msg = 'Missing entity ID from environment'
            tr_msg = _('Missing entity ID from environment')
            LOG.error(msg)
            raise exception.Unauthorized(tr_msg)

        host = self._get_sso_origin_host(request)

        ref = PROVIDERS.federation_api.get_idp_from_remote_id(remote_id)
        # NOTE(stevemar): the returned object is a simple dict that
        # contains the idp_id and remote_id.
        identity_provider = ref['idp_id']
        res = self.federated_authentication(request,
                                            identity_provider,
                                            protocol_id)
        token_id = res.headers['X-Subject-Token']
        return self.render_html_response(host, token_id)

    def federated_idp_specific_sso_auth(self, request, idp_id, protocol_id):
        host = self._get_sso_origin_host(request)

        # NOTE(lbragstad): We validate that the Identity Provider actually
        # exists in the Mapped authentication plugin.
        res = self.federated_authentication(request,
                                            idp_id,
                                            protocol_id)
        token_id = res.headers['X-Subject-Token']
        return self.render_html_response(host, token_id)

    def render_html_response(self, host, token_id):
        """Form an HTML Form from a template with autosubmit."""
        headers = [('Content-Type', 'text/html')]

        with open(CONF.federation.sso_callback_template) as template:
            src = string.Template(template.read())

        subs = {'host': host, 'token': token_id}
        body = src.substitute(subs)
        return webob.Response(body=body, status='200', charset='utf-8',
                              headerlist=headers)

    def _create_base_saml_assertion(self, context, auth):
        issuer = CONF.saml.idp_entity_id
        sp_id = auth['scope']['service_provider']['id']
        service_provider = PROVIDERS.federation_api.get_sp(sp_id)
        utils.assert_enabled_service_provider_object(service_provider)
        sp_url = service_provider['sp_url']

        token_id = auth['identity']['token']['id']
        token = PROVIDERS.token_provider_api.validate_token(token_id)

        if not token.project_scoped:
            action = _('Use a project scoped token when attempting to create '
                       'a SAML assertion')
            raise exception.ForbiddenAction(action=action)

        subject = token.user['name']
        role_names = []
        for role in token.roles:
            role_names.append(role['name'])
        project = token.project['name']
        # NOTE(rodrigods): the domain name is necessary in order to distinguish
        # between projects and users with the same name in different domains.
        project_domain_name = token.project_domain['name']
        subject_domain_name = token.user_domain['name']

        generator = keystone_idp.SAMLGenerator()
        response = generator.samlize_token(
            issuer, sp_url, subject, subject_domain_name,
            role_names, project, project_domain_name)
        return (response, service_provider)

    def _build_response_headers(self, service_provider):
        # URLs in header are encoded into bytes
        return [('Content-Type', 'text/xml'),
                ('X-sp-url', service_provider['sp_url'].encode('utf-8')),
                ('X-auth-url', service_provider['auth_url'].encode('utf-8'))]

    def create_saml_assertion(self, request, auth):
        """Exchange a scoped token for a SAML assertion.

        :param auth: Dictionary that contains a token and service provider ID
        :returns: SAML Assertion based on properties from the token
        """
        validation.lazy_validate(schema.saml_create, auth)
        t = self._create_base_saml_assertion(request.context_dict, auth)
        (response, service_provider) = t

        headers = self._build_response_headers(service_provider)
        return wsgi.render_response(
            body=response.to_string(),
            status=(http_client.OK, http_client.responses[http_client.OK]),
            headers=headers)

    def create_ecp_assertion(self, request, auth):
        """Exchange a scoped token for an ECP assertion.

        :param auth: Dictionary that contains a token and service provider ID
        :returns: ECP Assertion based on properties from the token
        """
        validation.lazy_validate(schema.saml_create, auth)
        t = self._create_base_saml_assertion(request.context_dict, auth)
        (saml_assertion, service_provider) = t
        relay_state_prefix = service_provider['relay_state_prefix']

        generator = keystone_idp.ECPGenerator()
        ecp_assertion = generator.generate_ecp(saml_assertion,
                                               relay_state_prefix)

        headers = self._build_response_headers(service_provider)
        return wsgi.render_response(
            body=ecp_assertion.to_string(),
            status=(http_client.OK, http_client.responses[http_client.OK]),
            headers=headers)

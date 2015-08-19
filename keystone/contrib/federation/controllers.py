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

from oslo_config import cfg
from oslo_log import log
import six
from six.moves import urllib
import webob

from keystone.auth import controllers as auth_controllers
from keystone.common import authorization
from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.common import wsgi
from keystone.contrib.federation import idp as keystone_idp
from keystone.contrib.federation import schema
from keystone.contrib.federation import utils
from keystone import exception
from keystone.i18n import _
from keystone.models import token_model


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class _ControllerBase(controller.V3Controller):
    """Base behaviors for federation controllers."""

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""

        path = '/OS-FEDERATION/' + cls.collection_name
        return super(_ControllerBase, cls).base_url(context, path=path)


@dependency.requires('federation_api')
class IdentityProvider(_ControllerBase):
    """Identity Provider representation."""
    collection_name = 'identity_providers'
    member_name = 'identity_provider'

    _mutable_parameters = frozenset(['description', 'enabled', 'remote_ids'])
    _public_parameters = frozenset(['id', 'enabled', 'description',
                                    'remote_ids', 'links'
                                    ])

    @classmethod
    def _add_related_links(cls, context, ref):
        """Add URLs for entities related with Identity Provider.

        Add URLs pointing to:
        - protocols tied to the Identity Provider

        """
        ref.setdefault('links', {})
        base_path = ref['links'].get('self')
        if base_path is None:
            base_path = '/'.join([IdentityProvider.base_url(context),
                                  ref['id']])
        for name in ['protocols']:
            ref['links'][name] = '/'.join([base_path, name])

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        id = ref.get('id')
        self_path = '/'.join([cls.base_url(context), id])
        ref.setdefault('links', {})
        ref['links']['self'] = self_path

    @classmethod
    def wrap_member(cls, context, ref):
        cls._add_self_referential_link(context, ref)
        cls._add_related_links(context, ref)
        ref = cls.filter_params(ref)
        return {cls.member_name: ref}

    @controller.protected()
    def create_identity_provider(self, context, idp_id, identity_provider):
        identity_provider = self._normalize_dict(identity_provider)
        identity_provider.setdefault('enabled', False)
        IdentityProvider.check_immutable_params(identity_provider)
        idp_ref = self.federation_api.create_idp(idp_id, identity_provider)
        response = IdentityProvider.wrap_member(context, idp_ref)
        return wsgi.render_response(body=response, status=('201', 'Created'))

    @controller.protected()
    def list_identity_providers(self, context):
        ref = self.federation_api.list_idps()
        ref = [self.filter_params(x) for x in ref]
        return IdentityProvider.wrap_collection(context, ref)

    @controller.protected()
    def get_identity_provider(self, context, idp_id):
        ref = self.federation_api.get_idp(idp_id)
        return IdentityProvider.wrap_member(context, ref)

    @controller.protected()
    def delete_identity_provider(self, context, idp_id):
        self.federation_api.delete_idp(idp_id)

    @controller.protected()
    def update_identity_provider(self, context, idp_id, identity_provider):
        identity_provider = self._normalize_dict(identity_provider)
        IdentityProvider.check_immutable_params(identity_provider)
        idp_ref = self.federation_api.update_idp(idp_id, identity_provider)
        return IdentityProvider.wrap_member(context, idp_ref)


@dependency.requires('federation_api')
class FederationProtocol(_ControllerBase):
    """A federation protocol representation.

    See IdentityProvider docstring for explanation on _mutable_parameters
    and _public_parameters class attributes.

    """
    collection_name = 'protocols'
    member_name = 'protocol'

    _public_parameters = frozenset(['id', 'mapping_id', 'links'])
    _mutable_parameters = frozenset(['mapping_id'])

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        """Add 'links' entry to the response dictionary.

        Calls IdentityProvider.base_url() class method, as it constructs
        proper URL along with the 'identity providers' part included.

        :param ref: response dictionary

        """
        ref.setdefault('links', {})
        base_path = ref['links'].get('identity_provider')
        if base_path is None:
            base_path = [IdentityProvider.base_url(context), ref['idp_id']]
            base_path = '/'.join(base_path)
        self_path = [base_path, 'protocols', ref['id']]
        self_path = '/'.join(self_path)
        ref['links']['self'] = self_path

    @classmethod
    def _add_related_links(cls, context, ref):
        """Add new entries to the 'links' subdictionary in the response.

        Adds 'identity_provider' key with URL pointing to related identity
        provider as a value.

        :param ref: response dictionary

        """
        ref.setdefault('links', {})
        base_path = '/'.join([IdentityProvider.base_url(context),
                              ref['idp_id']])
        ref['links']['identity_provider'] = base_path

    @classmethod
    def wrap_member(cls, context, ref):
        cls._add_related_links(context, ref)
        cls._add_self_referential_link(context, ref)
        ref = cls.filter_params(ref)
        return {cls.member_name: ref}

    @controller.protected()
    def create_protocol(self, context, idp_id, protocol_id, protocol):
        ref = self._normalize_dict(protocol)
        FederationProtocol.check_immutable_params(ref)
        ref = self.federation_api.create_protocol(idp_id, protocol_id, ref)
        response = FederationProtocol.wrap_member(context, ref)
        return wsgi.render_response(body=response, status=('201', 'Created'))

    @controller.protected()
    def update_protocol(self, context, idp_id, protocol_id, protocol):
        ref = self._normalize_dict(protocol)
        FederationProtocol.check_immutable_params(ref)
        ref = self.federation_api.update_protocol(idp_id, protocol_id,
                                                  protocol)
        return FederationProtocol.wrap_member(context, ref)

    @controller.protected()
    def get_protocol(self, context, idp_id, protocol_id):
        ref = self.federation_api.get_protocol(idp_id, protocol_id)
        return FederationProtocol.wrap_member(context, ref)

    @controller.protected()
    def list_protocols(self, context, idp_id):
        protocols_ref = self.federation_api.list_protocols(idp_id)
        protocols = list(protocols_ref)
        return FederationProtocol.wrap_collection(context, protocols)

    @controller.protected()
    def delete_protocol(self, context, idp_id, protocol_id):
        self.federation_api.delete_protocol(idp_id, protocol_id)


@dependency.requires('federation_api')
class MappingController(_ControllerBase):
    collection_name = 'mappings'
    member_name = 'mapping'

    @controller.protected()
    def create_mapping(self, context, mapping_id, mapping):
        ref = self._normalize_dict(mapping)
        utils.validate_mapping_structure(ref)
        mapping_ref = self.federation_api.create_mapping(mapping_id, ref)
        response = MappingController.wrap_member(context, mapping_ref)
        return wsgi.render_response(body=response, status=('201', 'Created'))

    @controller.protected()
    def list_mappings(self, context):
        ref = self.federation_api.list_mappings()
        return MappingController.wrap_collection(context, ref)

    @controller.protected()
    def get_mapping(self, context, mapping_id):
        ref = self.federation_api.get_mapping(mapping_id)
        return MappingController.wrap_member(context, ref)

    @controller.protected()
    def delete_mapping(self, context, mapping_id):
        self.federation_api.delete_mapping(mapping_id)

    @controller.protected()
    def update_mapping(self, context, mapping_id, mapping):
        mapping = self._normalize_dict(mapping)
        utils.validate_mapping_structure(mapping)
        mapping_ref = self.federation_api.update_mapping(mapping_id, mapping)
        return MappingController.wrap_member(context, mapping_ref)


@dependency.requires('federation_api')
class Auth(auth_controllers.Auth):

    def _get_sso_origin_host(self, context):
        """Validate and return originating dashboard URL.

        Make sure the parameter is specified in the request's URL as well its
        value belongs to a list of trusted dashboards.

        :param context: request's context
        :raises: exception.ValidationError: ``origin`` query parameter was not
            specified. The URL is deemed invalid.
        :raises: exception.Unauthorized: URL specified in origin query
            parameter does not exist in list of websso trusted dashboards.
        :returns: URL with the originating dashboard

        """
        if 'origin' in context['query_string']:
            origin = context['query_string'].get('origin')
            host = urllib.parse.unquote_plus(origin)
        else:
            msg = _('Request must have an origin query parameter')
            LOG.error(msg)
            raise exception.ValidationError(msg)

        if host not in CONF.federation.trusted_dashboard:
            msg = _('%(host)s is not a trusted dashboard host')
            msg = msg % {'host': host}
            LOG.error(msg)
            raise exception.Unauthorized(msg)

        return host

    def federated_authentication(self, context, identity_provider, protocol):
        """Authenticate from dedicated url endpoint.

        Build HTTP request body for federated authentication and inject
        it into the ``authenticate_for_token`` function.

        """
        auth = {
            'identity': {
                'methods': [protocol],
                protocol: {
                    'identity_provider': identity_provider,
                    'protocol': protocol
                }
            }
        }

        return self.authenticate_for_token(context, auth=auth)

    def federated_sso_auth(self, context, protocol_id):
        try:
            remote_id_name = utils.get_remote_id_parameter(protocol_id)
            remote_id = context['environment'][remote_id_name]
        except KeyError:
            msg = _('Missing entity ID from environment')
            LOG.error(msg)
            raise exception.Unauthorized(msg)

        host = self._get_sso_origin_host(context)

        ref = self.federation_api.get_idp_from_remote_id(remote_id)
        # NOTE(stevemar): the returned object is a simple dict that
        # contains the idp_id and remote_id.
        identity_provider = ref['idp_id']
        res = self.federated_authentication(context, identity_provider,
                                            protocol_id)
        token_id = res.headers['X-Subject-Token']
        return self.render_html_response(host, token_id)

    def federated_idp_specific_sso_auth(self, context, idp_id, protocol_id):
        host = self._get_sso_origin_host(context)

        # NOTE(lbragstad): We validate that the Identity Provider actually
        # exists in the Mapped authentication plugin.
        res = self.federated_authentication(context, idp_id, protocol_id)
        token_id = res.headers['X-Subject-Token']
        return self.render_html_response(host, token_id)

    def render_html_response(self, host, token_id):
        """Forms an HTML Form from a template with autosubmit."""

        headers = [('Content-Type', 'text/html')]

        with open(CONF.federation.sso_callback_template) as template:
            src = string.Template(template.read())

        subs = {'host': host, 'token': token_id}
        body = src.substitute(subs)
        return webob.Response(body=body, status='200',
                              headerlist=headers)

    def _create_base_saml_assertion(self, context, auth):
        issuer = CONF.saml.idp_entity_id
        sp_id = auth['scope']['service_provider']['id']
        service_provider = self.federation_api.get_sp(sp_id)
        utils.assert_enabled_service_provider_object(service_provider)
        sp_url = service_provider.get('sp_url')

        token_id = auth['identity']['token']['id']
        token_data = self.token_provider_api.validate_token(token_id)
        token_ref = token_model.KeystoneToken(token_id, token_data)

        if not token_ref.project_scoped:
            action = _('Use a project scoped token when attempting to create '
                       'a SAML assertion')
            raise exception.ForbiddenAction(action=action)

        subject = token_ref.user_name
        roles = token_ref.role_names
        project = token_ref.project_name
        # NOTE(rodrigods): the domain name is necessary in order to distinguish
        # between projects and users with the same name in different domains.
        project_domain_name = token_ref.project_domain_name
        subject_domain_name = token_ref.user_domain_name

        generator = keystone_idp.SAMLGenerator()
        response = generator.samlize_token(
            issuer, sp_url, subject, subject_domain_name,
            roles, project, project_domain_name)
        return (response, service_provider)

    def _build_response_headers(self, service_provider):
        return [('Content-Type', 'text/xml'),
                ('X-sp-url', six.binary_type(service_provider['sp_url'])),
                ('X-auth-url', six.binary_type(service_provider['auth_url']))]

    @validation.validated(schema.saml_create, 'auth')
    def create_saml_assertion(self, context, auth):
        """Exchange a scoped token for a SAML assertion.

        :param auth: Dictionary that contains a token and service provider ID
        :returns: SAML Assertion based on properties from the token
        """

        t = self._create_base_saml_assertion(context, auth)
        (response, service_provider) = t

        headers = self._build_response_headers(service_provider)
        return wsgi.render_response(body=response.to_string(),
                                    status=('200', 'OK'),
                                    headers=headers)

    @validation.validated(schema.saml_create, 'auth')
    def create_ecp_assertion(self, context, auth):
        """Exchange a scoped token for an ECP assertion.

        :param auth: Dictionary that contains a token and service provider ID
        :returns: ECP Assertion based on properties from the token
        """

        t = self._create_base_saml_assertion(context, auth)
        (saml_assertion, service_provider) = t
        relay_state_prefix = service_provider.get('relay_state_prefix')

        generator = keystone_idp.ECPGenerator()
        ecp_assertion = generator.generate_ecp(saml_assertion,
                                               relay_state_prefix)

        headers = self._build_response_headers(service_provider)
        return wsgi.render_response(body=ecp_assertion.to_string(),
                                    status=('200', 'OK'),
                                    headers=headers)


@dependency.requires('assignment_api', 'resource_api')
class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_domain

    @controller.protected()
    def list_domains_for_groups(self, context):
        """List all domains available to an authenticated user's groups.

        :param context: request context
        :returns: list of accessible domains

        """
        auth_context = context['environment'][authorization.AUTH_CONTEXT_ENV]
        domains = self.assignment_api.list_domains_for_groups(
            auth_context['group_ids'])
        return DomainV3.wrap_collection(context, domains)


@dependency.requires('assignment_api', 'resource_api')
class ProjectAssignmentV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectAssignmentV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project

    @controller.protected()
    def list_projects_for_groups(self, context):
        """List all projects available to an authenticated user's groups.

        :param context: request context
        :returns: list of accessible projects

        """
        auth_context = context['environment'][authorization.AUTH_CONTEXT_ENV]
        projects = self.assignment_api.list_projects_for_groups(
            auth_context['group_ids'])
        return ProjectAssignmentV3.wrap_collection(context, projects)


@dependency.requires('federation_api')
class ServiceProvider(_ControllerBase):
    """Service Provider representation."""

    collection_name = 'service_providers'
    member_name = 'service_provider'

    _mutable_parameters = frozenset(['auth_url', 'description', 'enabled',
                                     'relay_state_prefix', 'sp_url'])
    _public_parameters = frozenset(['auth_url', 'id', 'enabled', 'description',
                                    'links', 'relay_state_prefix', 'sp_url'])

    @controller.protected()
    @validation.validated(schema.service_provider_create, 'service_provider')
    def create_service_provider(self, context, sp_id, service_provider):
        service_provider = self._normalize_dict(service_provider)
        service_provider.setdefault('enabled', False)
        service_provider.setdefault('relay_state_prefix',
                                    CONF.saml.relay_state_prefix)
        ServiceProvider.check_immutable_params(service_provider)
        sp_ref = self.federation_api.create_sp(sp_id, service_provider)
        response = ServiceProvider.wrap_member(context, sp_ref)
        return wsgi.render_response(body=response, status=('201', 'Created'))

    @controller.protected()
    def list_service_providers(self, context):
        ref = self.federation_api.list_sps()
        ref = [self.filter_params(x) for x in ref]
        return ServiceProvider.wrap_collection(context, ref)

    @controller.protected()
    def get_service_provider(self, context, sp_id):
        ref = self.federation_api.get_sp(sp_id)
        return ServiceProvider.wrap_member(context, ref)

    @controller.protected()
    def delete_service_provider(self, context, sp_id):
        self.federation_api.delete_sp(sp_id)

    @controller.protected()
    @validation.validated(schema.service_provider_update, 'service_provider')
    def update_service_provider(self, context, sp_id, service_provider):
        service_provider = self._normalize_dict(service_provider)
        ServiceProvider.check_immutable_params(service_provider)
        sp_ref = self.federation_api.update_sp(sp_id, service_provider)
        return ServiceProvider.wrap_member(context, sp_ref)


class SAMLMetadataV3(_ControllerBase):
    member_name = 'metadata'

    def get_metadata(self, context):
        metadata_path = CONF.saml.idp_metadata_path
        try:
            with open(metadata_path, 'r') as metadata_handler:
                metadata = metadata_handler.read()
        except IOError as e:
            # Raise HTTP 500 in case Metadata file cannot be read.
            raise exception.MetadataFileError(reason=e)
        return wsgi.render_response(body=metadata, status=('200', 'OK'),
                                    headers=[('Content-Type', 'text/xml')])

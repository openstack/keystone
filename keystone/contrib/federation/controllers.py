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

"""Extensions supporting Federation."""

from keystone.auth import controllers as auth_controllers
from keystone.common import authorization
from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
from keystone import config
from keystone.contrib.federation import utils
from keystone import exception


CONF = config.CONF


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

    _mutable_parameters = frozenset(['description', 'enabled'])
    _public_parameters = frozenset(['id', 'enabled', 'description', 'links'])

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

    #TODO(marek-denis): Implement, when mapping engine is ready
    def _delete_tokens_issued_by_idp(self, idp_id):
        """Delete tokens created upon authentication from an IdP

        After the IdP is deregistered, users authenticating via such IdP should
        no longer be allowed to use federated services. Thus, delete all the
        tokens issued upon authentication from IdP with idp_id id

        :param idp_id: id of Identity Provider for which related tokens should
                       be removed.

        """
        raise exception.NotImplemented()

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


class Auth(auth_controllers.Auth):

    def federated_authentication(self, context, identity_provider, protocol):
        """Authenticate from dedicated url endpoint.

        Build HTTP request body for federated authentication and inject
        it into the ``authenticate_for_token`` function.

        """
        auth = {
            'identity': {
                'methods': ['saml2'],
                'saml2': {
                    'identity_provider': identity_provider,
                    'protocol': protocol
                }
            }
        }

        return self.authenticate_for_token(context, auth=auth)


@dependency.requires('assignment_api')
class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = self.assignment_api.get_domain

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


@dependency.requires('assignment_api')
class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = self.assignment_api.get_project

    @controller.protected()
    def list_projects_for_groups(self, context):
        """List all projects available to an authenticated user's groups.

        :param context: request context
        :returns: list of accessible projects

        """
        auth_context = context['environment'][authorization.AUTH_CONTEXT_ENV]
        projects = self.assignment_api.list_projects_for_groups(
            auth_context['group_ids'])
        return ProjectV3.wrap_collection(context, projects)

# Copyright 2013 OpenStack Foundation
#
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

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
from oslo_serialization import jsonutils
import six
from six.moves.urllib import parse

from keystone.common import controller as common_controller
from keystone.common import dependency
from keystone.common import utils
from keystone.contrib.federation import constants as federation_constants
from keystone import exception
from keystone.i18n import _, _LE
from keystone import token
from keystone.token import provider


LOG = log.getLogger(__name__)
CONF = cfg.CONF


@dependency.requires('catalog_api', 'resource_api')
class V2TokenDataHelper(object):
    """Creates V2 token data."""

    def v3_to_v2_token(self, v3_token_data):
        token_data = {}
        # Build v2 token
        v3_token = v3_token_data['token']

        token = {}
        token['expires'] = v3_token.get('expires_at')
        token['issued_at'] = v3_token.get('issued_at')
        token['audit_ids'] = v3_token.get('audit_ids')

        # Bail immediately if this is a domain-scoped token, which is not
        # supported by the v2 API at all.
        if 'domain' in v3_token:
            raise exception.Unauthorized(_(
                'Domains are not supported by the v2 API. Please use the v3 '
                'API instead.'))

        # Bail if this is a project-scoped token outside the default domain,
        # which may result in a namespace collision with a project inside the
        # default domain.
        if 'project' in v3_token:
            if (v3_token['project']['domain']['id'] !=
                    CONF.identity.default_domain_id):
                raise exception.Unauthorized(_(
                    'Project not found in the default domain (please use the '
                    'v3 API instead): %s') % v3_token['project']['id'])

            # v3 token_data does not contain all tenant attributes
            tenant = self.resource_api.get_project(
                v3_token['project']['id'])
            token['tenant'] = common_controller.V2Controller.filter_domain_id(
                tenant)
        token_data['token'] = token

        # Build v2 user
        v3_user = v3_token['user']

        # Bail if this is a token outside the default domain,
        # which may result in a namespace collision with a project inside the
        # default domain.
        if ('domain' in v3_user and v3_user['domain']['id'] !=
                CONF.identity.default_domain_id):
            raise exception.Unauthorized(_(
                'User not found in the default domain (please use the v3 API '
                'instead): %s') % v3_user['id'])

        user = common_controller.V2Controller.v3_to_v2_user(v3_user)

        # Maintain Trust Data
        if 'OS-TRUST:trust' in v3_token:
            v3_trust_data = v3_token['OS-TRUST:trust']
            token_data['trust'] = {
                'trustee_user_id': v3_trust_data['trustee_user']['id'],
                'id': v3_trust_data['id'],
                'trustor_user_id': v3_trust_data['trustor_user']['id'],
                'impersonation': v3_trust_data['impersonation']
            }

        # Set user roles
        user['roles'] = []
        role_ids = []
        for role in v3_token.get('roles', []):
            user['roles'].append(role)
        user['roles_links'] = []

        token_data['user'] = user

        # Get and build v2 service catalog
        token_data['serviceCatalog'] = []
        if 'tenant' in token:
            catalog_ref = self.catalog_api.get_catalog(
                user['id'], token['tenant']['id'])
            if catalog_ref:
                token_data['serviceCatalog'] = self.format_catalog(catalog_ref)

        # Build v2 metadata
        metadata = {}
        metadata['roles'] = role_ids
        # Setting is_admin to keep consistency in v2 response
        metadata['is_admin'] = 0
        token_data['metadata'] = metadata

        return {'access': token_data}

    @classmethod
    def format_token(cls, token_ref, roles_ref=None, catalog_ref=None,
                     trust_ref=None):
        audit_info = None
        user_ref = token_ref['user']
        metadata_ref = token_ref['metadata']
        if roles_ref is None:
            roles_ref = []
        expires = token_ref.get('expires', provider.default_expire_time())
        if expires is not None:
            if not isinstance(expires, six.text_type):
                expires = utils.isotime(expires)

        token_data = token_ref.get('token_data')
        if token_data:
            token_audit = token_data.get(
                'access', token_data).get('token', {}).get('audit_ids')
            audit_info = token_audit

        if audit_info is None:
            audit_info = provider.audit_info(token_ref.get('parent_audit_id'))

        o = {'access': {'token': {'id': token_ref['id'],
                                  'expires': expires,
                                  'issued_at': utils.strtime(),
                                  'audit_ids': audit_info
                                  },
                        'user': {'id': user_ref['id'],
                                 'name': user_ref['name'],
                                 'username': user_ref['name'],
                                 'roles': roles_ref,
                                 'roles_links': metadata_ref.get('roles_links',
                                                                 [])
                                 }
                        }
             }
        if 'bind' in token_ref:
            o['access']['token']['bind'] = token_ref['bind']
        if 'tenant' in token_ref and token_ref['tenant']:
            token_ref['tenant']['enabled'] = True
            o['access']['token']['tenant'] = token_ref['tenant']
        if catalog_ref is not None:
            o['access']['serviceCatalog'] = V2TokenDataHelper.format_catalog(
                catalog_ref)
        if metadata_ref:
            if 'is_admin' in metadata_ref:
                o['access']['metadata'] = {'is_admin':
                                           metadata_ref['is_admin']}
            else:
                o['access']['metadata'] = {'is_admin': 0}
        if 'roles' in metadata_ref:
            o['access']['metadata']['roles'] = metadata_ref['roles']
        if CONF.trust.enabled and trust_ref:
            o['access']['trust'] = {'trustee_user_id':
                                    trust_ref['trustee_user_id'],
                                    'id': trust_ref['id'],
                                    'trustor_user_id':
                                    trust_ref['trustor_user_id'],
                                    'impersonation':
                                    trust_ref['impersonation']
                                    }
        return o

    @classmethod
    def format_catalog(cls, catalog_ref):
        """Munge catalogs from internal to output format
        Internal catalogs look like::

          {$REGION: {
              {$SERVICE: {
                  $key1: $value1,
                  ...
                  }
              }
          }

        The legacy api wants them to look like::

          [{'name': $SERVICE[name],
            'type': $SERVICE,
            'endpoints': [{
                'tenantId': $tenant_id,
                ...
                'region': $REGION,
                }],
            'endpoints_links': [],
           }]

        """
        if not catalog_ref:
            return []

        services = {}
        for region, region_ref in catalog_ref.items():
            for service, service_ref in region_ref.items():
                new_service_ref = services.get(service, {})
                new_service_ref['name'] = service_ref.pop('name')
                new_service_ref['type'] = service
                new_service_ref['endpoints_links'] = []
                service_ref['region'] = region

                endpoints_ref = new_service_ref.get('endpoints', [])
                endpoints_ref.append(service_ref)

                new_service_ref['endpoints'] = endpoints_ref
                services[service] = new_service_ref

        return list(services.values())


@dependency.requires('assignment_api', 'catalog_api', 'federation_api',
                     'identity_api', 'resource_api', 'role_api', 'trust_api')
class V3TokenDataHelper(object):
    """Token data helper."""
    def __init__(self):
        # Keep __init__ around to ensure dependency injection works.
        super(V3TokenDataHelper, self).__init__()

    def _get_filtered_domain(self, domain_id):
        domain_ref = self.resource_api.get_domain(domain_id)
        return {'id': domain_ref['id'], 'name': domain_ref['name']}

    def _get_filtered_project(self, project_id):
        project_ref = self.resource_api.get_project(project_id)
        filtered_project = {
            'id': project_ref['id'],
            'name': project_ref['name']}
        filtered_project['domain'] = self._get_filtered_domain(
            project_ref['domain_id'])
        return filtered_project

    def _populate_scope(self, token_data, domain_id, project_id):
        if 'domain' in token_data or 'project' in token_data:
            # scope already exist, no need to populate it again
            return

        if domain_id:
            token_data['domain'] = self._get_filtered_domain(domain_id)
        if project_id:
            token_data['project'] = self._get_filtered_project(project_id)

    def _get_roles_for_user(self, user_id, domain_id, project_id):
        roles = []
        if domain_id:
            roles = self.assignment_api.get_roles_for_user_and_domain(
                user_id, domain_id)
        if project_id:
            roles = self.assignment_api.get_roles_for_user_and_project(
                user_id, project_id)
        return [self.role_api.get_role(role_id) for role_id in roles]

    def populate_roles_for_groups(self, token_data, group_ids,
                                  project_id=None, domain_id=None,
                                  user_id=None):
        """Populate roles basing on provided groups and project/domain

        Used for ephemeral users with dynamically assigned groups.
        This method does not return anything, yet it modifies token_data in
        place.

        :param token_data: a dictionary used for building token response
        :group_ids: list of group IDs a user is a member of
        :project_id: project ID to scope to
        :domain_id: domain ID to scope to
        :user_id: user ID

        :raises: exception.Unauthorized - when no roles were found for a
            (group_ids, project_id) or (group_ids, domain_id) pairs.

        """
        def check_roles(roles, user_id, project_id, domain_id):
            # User was granted roles so simply exit this function.
            if roles:
                return
            if project_id:
                msg = _('User %(user_id)s has no access '
                        'to project %(project_id)s') % {
                            'user_id': user_id,
                            'project_id': project_id}
            elif domain_id:
                msg = _('User %(user_id)s has no access '
                        'to domain %(domain_id)s') % {
                            'user_id': user_id,
                            'domain_id': domain_id}
            # Since no roles were found a user is not authorized to
            # perform any operations. Raise an exception with
            # appropriate error message.
            raise exception.Unauthorized(msg)

        roles = self.assignment_api.get_roles_for_groups(group_ids,
                                                         project_id,
                                                         domain_id)
        check_roles(roles, user_id, project_id, domain_id)
        token_data['roles'] = roles

    def _populate_user(self, token_data, user_id, trust):
        if 'user' in token_data:
            # no need to repopulate user if it already exists
            return

        user_ref = self.identity_api.get_user(user_id)
        if CONF.trust.enabled and trust and 'OS-TRUST:trust' not in token_data:
            trustor_user_ref = (self.identity_api.get_user(
                                trust['trustor_user_id']))
            try:
                self.identity_api.assert_user_enabled(trust['trustor_user_id'])
            except AssertionError:
                raise exception.Forbidden(_('Trustor is disabled.'))
            if trust['impersonation']:
                user_ref = trustor_user_ref
            token_data['OS-TRUST:trust'] = (
                {
                    'id': trust['id'],
                    'trustor_user': {'id': trust['trustor_user_id']},
                    'trustee_user': {'id': trust['trustee_user_id']},
                    'impersonation': trust['impersonation']
                })
        filtered_user = {
            'id': user_ref['id'],
            'name': user_ref['name'],
            'domain': self._get_filtered_domain(user_ref['domain_id'])}
        token_data['user'] = filtered_user

    def _populate_oauth_section(self, token_data, access_token):
        if access_token:
            access_token_id = access_token['id']
            consumer_id = access_token['consumer_id']
            token_data['OS-OAUTH1'] = ({'access_token_id': access_token_id,
                                        'consumer_id': consumer_id})

    def _populate_roles(self, token_data, user_id, domain_id, project_id,
                        trust, access_token):
        if 'roles' in token_data:
            # no need to repopulate roles
            return

        if access_token:
            filtered_roles = []
            authed_role_ids = jsonutils.loads(access_token['role_ids'])
            all_roles = self.role_api.list_roles()
            for role in all_roles:
                for authed_role in authed_role_ids:
                    if authed_role == role['id']:
                        filtered_roles.append({'id': role['id'],
                                               'name': role['name']})
            token_data['roles'] = filtered_roles
            return

        if CONF.trust.enabled and trust:
            token_user_id = trust['trustor_user_id']
            token_project_id = trust['project_id']
            # trusts do not support domains yet
            token_domain_id = None
        else:
            token_user_id = user_id
            token_project_id = project_id
            token_domain_id = domain_id

        if token_domain_id or token_project_id:
            roles = self._get_roles_for_user(token_user_id,
                                             token_domain_id,
                                             token_project_id)
            filtered_roles = []
            if CONF.trust.enabled and trust:
                for trust_role in trust['roles']:
                    match_roles = [x for x in roles
                                   if x['id'] == trust_role['id']]
                    if match_roles:
                        filtered_roles.append(match_roles[0])
                    else:
                        raise exception.Forbidden(
                            _('Trustee has no delegated roles.'))
            else:
                for role in roles:
                    filtered_roles.append({'id': role['id'],
                                           'name': role['name']})

            # user has no project or domain roles, therefore access denied
            if not filtered_roles:
                if token_project_id:
                    msg = _('User %(user_id)s has no access '
                            'to project %(project_id)s') % {
                                'user_id': user_id,
                                'project_id': token_project_id}
                else:
                    msg = _('User %(user_id)s has no access '
                            'to domain %(domain_id)s') % {
                                'user_id': user_id,
                                'domain_id': token_domain_id}
                LOG.debug(msg)
                raise exception.Unauthorized(msg)

            token_data['roles'] = filtered_roles

    def _populate_service_catalog(self, token_data, user_id,
                                  domain_id, project_id, trust):
        if 'catalog' in token_data:
            # no need to repopulate service catalog
            return

        if CONF.trust.enabled and trust:
            user_id = trust['trustor_user_id']
        if project_id or domain_id:
            service_catalog = self.catalog_api.get_v3_catalog(
                user_id, project_id)
            # TODO(ayoung): Enforce Endpoints for trust
            token_data['catalog'] = service_catalog

    def _populate_service_providers(self, token_data):
        if 'service_providers' in token_data:
            return

        service_providers = self.federation_api.get_enabled_service_providers()
        if service_providers:
            token_data['service_providers'] = service_providers

    def _populate_token_dates(self, token_data, expires=None, trust=None,
                              issued_at=None):
        if not expires:
            expires = provider.default_expire_time()
        if not isinstance(expires, six.string_types):
            expires = utils.isotime(expires, subsecond=True)
        token_data['expires_at'] = expires
        token_data['issued_at'] = (issued_at or
                                   utils.isotime(subsecond=True))

    def _populate_audit_info(self, token_data, audit_info=None):
        if audit_info is None or isinstance(audit_info, six.string_types):
            token_data['audit_ids'] = provider.audit_info(audit_info)
        elif isinstance(audit_info, list):
            token_data['audit_ids'] = audit_info
        else:
            msg = (_('Invalid audit info data type: %(data)s (%(type)s)') %
                   {'data': audit_info, 'type': type(audit_info)})
            LOG.error(msg)
            raise exception.UnexpectedError(msg)

    def get_token_data(self, user_id, method_names, extras=None,
                       domain_id=None, project_id=None, expires=None,
                       trust=None, token=None, include_catalog=True,
                       bind=None, access_token=None, issued_at=None,
                       audit_info=None):
        if extras is None:
            extras = {}
        if extras:
            versionutils.deprecated(
                what='passing token data with "extras"',
                as_of=versionutils.deprecated.KILO,
                in_favor_of='well-defined APIs')(lambda: None)()
        token_data = {'methods': method_names,
                      'extras': extras}

        # We've probably already written these to the token
        if token:
            for x in ('roles', 'user', 'catalog', 'project', 'domain'):
                if x in token:
                    token_data[x] = token[x]

        if CONF.trust.enabled and trust:
            if user_id != trust['trustee_user_id']:
                raise exception.Forbidden(_('User is not a trustee.'))

        if bind:
            token_data['bind'] = bind

        self._populate_scope(token_data, domain_id, project_id)
        self._populate_user(token_data, user_id, trust)
        self._populate_roles(token_data, user_id, domain_id, project_id, trust,
                             access_token)
        self._populate_audit_info(token_data, audit_info)

        if include_catalog:
            self._populate_service_catalog(token_data, user_id, domain_id,
                                           project_id, trust)
        self._populate_service_providers(token_data)
        self._populate_token_dates(token_data, expires=expires, trust=trust,
                                   issued_at=issued_at)
        self._populate_oauth_section(token_data, access_token)
        return {'token': token_data}


@dependency.requires('catalog_api', 'identity_api', 'oauth_api',
                     'resource_api', 'role_api', 'trust_api')
class BaseProvider(provider.Provider):
    def __init__(self, *args, **kwargs):
        super(BaseProvider, self).__init__(*args, **kwargs)
        self.v3_token_data_helper = V3TokenDataHelper()
        self.v2_token_data_helper = V2TokenDataHelper()

    def get_token_version(self, token_data):
        if token_data and isinstance(token_data, dict):
            if 'token_version' in token_data:
                if token_data['token_version'] in token.provider.VERSIONS:
                    return token_data['token_version']
            # FIXME(morganfainberg): deprecate the following logic in future
            # revisions. It is better to just specify the token_version in
            # the token_data itself. This way we can support future versions
            # that might have the same fields.
            if 'access' in token_data:
                return token.provider.V2
            if 'token' in token_data and 'methods' in token_data['token']:
                return token.provider.V3
        raise exception.UnsupportedTokenVersionException()

    def issue_v2_token(self, token_ref, roles_ref=None,
                       catalog_ref=None):
        metadata_ref = token_ref['metadata']
        trust_ref = None
        if CONF.trust.enabled and metadata_ref and 'trust_id' in metadata_ref:
            trust_ref = self.trust_api.get_trust(metadata_ref['trust_id'])

        token_data = self.v2_token_data_helper.format_token(
            token_ref, roles_ref, catalog_ref, trust_ref)
        token_id = self._get_token_id(token_data)
        token_data['access']['token']['id'] = token_id
        return token_id, token_data

    def _is_mapped_token(self, auth_context):
        return (federation_constants.IDENTITY_PROVIDER in auth_context and
                federation_constants.PROTOCOL in auth_context)

    def issue_v3_token(self, user_id, method_names, expires_at=None,
                       project_id=None, domain_id=None, auth_context=None,
                       trust=None, metadata_ref=None, include_catalog=True,
                       parent_audit_id=None):
        if auth_context and auth_context.get('bind'):
            # NOTE(lbragstad): Check if the token provider being used actually
            # supports bind authentication methods before proceeding.
            if not self._supports_bind_authentication:
                raise exception.NotImplemented(_(
                    'The configured token provider does not support bind '
                    'authentication.'))

        # for V2, trust is stashed in metadata_ref
        if (CONF.trust.enabled and not trust and metadata_ref and
                'trust_id' in metadata_ref):
            trust = self.trust_api.get_trust(metadata_ref['trust_id'])

        token_ref = None
        if auth_context and self._is_mapped_token(auth_context):
            token_ref = self._handle_mapped_tokens(
                auth_context, project_id, domain_id)

        access_token = None
        if 'oauth1' in method_names:
            access_token_id = auth_context['access_token_id']
            access_token = self.oauth_api.get_access_token(access_token_id)

        token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            method_names,
            auth_context.get('extras') if auth_context else None,
            domain_id=domain_id,
            project_id=project_id,
            expires=expires_at,
            trust=trust,
            bind=auth_context.get('bind') if auth_context else None,
            token=token_ref,
            include_catalog=include_catalog,
            access_token=access_token,
            audit_info=parent_audit_id)

        token_id = self._get_token_id(token_data)
        return token_id, token_data

    def _handle_mapped_tokens(self, auth_context, project_id, domain_id):
        user_id = auth_context['user_id']
        group_ids = auth_context['group_ids']
        idp = auth_context[federation_constants.IDENTITY_PROVIDER]
        protocol = auth_context[federation_constants.PROTOCOL]
        token_data = {
            'user': {
                'id': user_id,
                'name': parse.unquote(user_id),
                federation_constants.FEDERATION: {
                    'groups': [{'id': x} for x in group_ids],
                    'identity_provider': {'id': idp},
                    'protocol': {'id': protocol}
                },
                'domain': {
                    'id': CONF.federation.federated_domain_name,
                    'name': CONF.federation.federated_domain_name
                }
            }
        }

        if project_id or domain_id:
            self.v3_token_data_helper.populate_roles_for_groups(
                token_data, group_ids, project_id, domain_id, user_id)

        return token_data

    def _verify_token_ref(self, token_ref):
        """Verify and return the given token_ref."""
        if not token_ref:
            raise exception.Unauthorized()
        return token_ref

    def _assert_is_not_federation_token(self, token_ref):
        """Make sure we aren't using v2 auth on a federation token."""
        token_data = token_ref.get('token_data')
        if (token_data and self.get_token_version(token_data) ==
                token.provider.V3):
            if 'OS-FEDERATION' in token_data['token']['user']:
                msg = _('Attempting to use OS-FEDERATION token with V2 '
                        'Identity Service, use V3 Authentication')
                raise exception.Unauthorized(msg)

    def _assert_default_domain(self, token_ref):
        """Make sure we are operating on default domain only."""
        if (token_ref.get('token_data') and
                self.get_token_version(token_ref.get('token_data')) ==
                token.provider.V3):
            # this is a V3 token
            msg = _('Non-default domain is not supported')
            # user in a non-default is prohibited
            if (token_ref['token_data']['token']['user']['domain']['id'] !=
                    CONF.identity.default_domain_id):
                raise exception.Unauthorized(msg)
            # domain scoping is prohibited
            if token_ref['token_data']['token'].get('domain'):
                raise exception.Unauthorized(
                    _('Domain scoped token is not supported'))
            # project in non-default domain is prohibited
            if token_ref['token_data']['token'].get('project'):
                project = token_ref['token_data']['token']['project']
                project_domain_id = project['domain']['id']
                # scoped to project in non-default domain is prohibited
                if project_domain_id != CONF.identity.default_domain_id:
                    raise exception.Unauthorized(msg)
            # if token is scoped to trust, both trustor and trustee must
            # be in the default domain. Furthermore, the delegated project
            # must also be in the default domain
            metadata_ref = token_ref['metadata']
            if CONF.trust.enabled and 'trust_id' in metadata_ref:
                trust_ref = self.trust_api.get_trust(metadata_ref['trust_id'])
                trustee_user_ref = self.identity_api.get_user(
                    trust_ref['trustee_user_id'])
                if (trustee_user_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)
                trustor_user_ref = self.identity_api.get_user(
                    trust_ref['trustor_user_id'])
                if (trustor_user_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)
                project_ref = self.resource_api.get_project(
                    trust_ref['project_id'])
                if (project_ref['domain_id'] !=
                        CONF.identity.default_domain_id):
                    raise exception.Unauthorized(msg)

    def validate_v2_token(self, token_ref):
        try:
            self._assert_is_not_federation_token(token_ref)
            self._assert_default_domain(token_ref)
            # FIXME(gyee): performance or correctness? Should we return the
            # cached token or reconstruct it? Obviously if we are going with
            # the cached token, any role, project, or domain name changes
            # will not be reflected. One may argue that with PKI tokens,
            # we are essentially doing cached token validation anyway.
            # Lets go with the cached token strategy. Since token
            # management layer is now pluggable, one can always provide
            # their own implementation to suit their needs.
            token_data = token_ref.get('token_data')
            if (self.get_token_version(token_data) != token.provider.V2):
                # Validate the V3 token as V2
                token_data = self.v2_token_data_helper.v3_to_v2_token(
                    token_data)

            trust_id = token_data['access'].get('trust', {}).get('id')
            if trust_id:
                # token trust validation
                self.trust_api.get_trust(trust_id)

            return token_data
        except exception.ValidationError as e:
            LOG.exception(_LE('Failed to validate token'))
            raise exception.TokenNotFound(e)

    def validate_v3_token(self, token_ref):
        # FIXME(gyee): performance or correctness? Should we return the
        # cached token or reconstruct it? Obviously if we are going with
        # the cached token, any role, project, or domain name changes
        # will not be reflected. One may argue that with PKI tokens,
        # we are essentially doing cached token validation anyway.
        # Lets go with the cached token strategy. Since token
        # management layer is now pluggable, one can always provide
        # their own implementation to suit their needs.

        trust_id = token_ref.get('trust_id')
        if trust_id:
            # token trust validation
            self.trust_api.get_trust(trust_id)

        token_data = token_ref.get('token_data')
        if not token_data or 'token' not in token_data:
            # token ref is created by V2 API
            project_id = None
            project_ref = token_ref.get('tenant')
            if project_ref:
                project_id = project_ref['id']

            issued_at = token_ref['token_data']['access']['token']['issued_at']
            audit = token_ref['token_data']['access']['token'].get('audit_ids')

            token_data = self.v3_token_data_helper.get_token_data(
                token_ref['user']['id'],
                ['password', 'token'],
                project_id=project_id,
                bind=token_ref.get('bind'),
                expires=token_ref['expires'],
                issued_at=issued_at,
                audit_info=audit)
        return token_data

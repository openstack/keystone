import json
import subprocess
import uuid

from keystone.common import cms
from keystone.common import controller
from keystone.common import dependency
from keystone.common import logging
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.openstack.common import timeutils
from keystone.token import core

CONF = config.CONF
LOG = logging.getLogger(__name__)
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


class ExternalAuthNotApplicable(Exception):
    """External authentication is not applicable."""
    pass


@dependency.requires('catalog_api', 'trust_api', 'token_api')
class Auth(controller.V2Controller):
    def ca_cert(self, context, auth=None):
        ca_file = open(CONF.signing.ca_certs, 'r')
        data = ca_file.read()
        ca_file.close()
        return data

    def signing_cert(self, context, auth=None):
        cert_file = open(CONF.signing.certfile, 'r')
        data = cert_file.read()
        cert_file.close()
        return data

    def authenticate(self, context, auth=None):
        """Authenticate credentials and return a token.

        Accept auth as a dict that looks like::

            {
                "auth":{
                    "passwordCredentials":{
                        "username":"test_user",
                        "password":"mypass"
                    },
                    "tenantName":"customer-x"
                }
            }

        In this case, tenant is optional, if not provided the token will be
        considered "unscoped" and can later be used to get a scoped token.

        Alternatively, this call accepts auth with only a token and tenant
        that will return a token that is scoped to that tenant.
        """

        if auth is None:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')

        auth_token_data = None

        if "token" in auth:
            # Try to authenticate using a token
            auth_info = self._authenticate_token(
                context, auth)
        else:
            # Try external authentication
            try:
                auth_info = self._authenticate_external(
                    context, auth)
            except ExternalAuthNotApplicable:
                # Try local authentication
                auth_info = self._authenticate_local(
                    context, auth)

        user_ref, tenant_ref, metadata_ref, expiry = auth_info
        core.validate_auth_info(self, context, user_ref, tenant_ref)
        trust_id = metadata_ref.get('trust_id')
        user_ref = self._filter_domain_id(user_ref)
        if tenant_ref:
            tenant_ref = self._filter_domain_id(tenant_ref)
        auth_token_data = self._get_auth_token_data(user_ref,
                                                    tenant_ref,
                                                    metadata_ref,
                                                    expiry)

        if tenant_ref:
            catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'],
                metadata=metadata_ref)
        else:
            catalog_ref = {}

        auth_token_data['id'] = 'placeholder'

        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            role_ref = self.identity_api.get_role(context, role_id)
            roles_ref.append(dict(name=role_ref['name']))

        token_data = Auth.format_token(auth_token_data, roles_ref)

        service_catalog = Auth.format_catalog(catalog_ref)
        token_data['access']['serviceCatalog'] = service_catalog

        if CONF.signing.token_format == 'UUID':
            token_id = uuid.uuid4().hex
        elif CONF.signing.token_format == 'PKI':
            try:
                token_id = cms.cms_sign_token(json.dumps(token_data),
                                              CONF.signing.certfile,
                                              CONF.signing.keyfile)
            except subprocess.CalledProcessError:
                raise exception.UnexpectedError(_(
                    'Unable to sign token.'))
        else:
            raise exception.UnexpectedError(_(
                'Invalid value for token_format: %s.'
                '  Allowed values are PKI or UUID.') %
                CONF.signing.token_format)
        try:
            self.token_api.create_token(
                context, token_id, dict(key=token_id,
                                        id=token_id,
                                        expires=auth_token_data['expires'],
                                        user=user_ref,
                                        tenant=tenant_ref,
                                        metadata=metadata_ref,
                                        trust_id=trust_id))
        except Exception as e:
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self.token_api.get_token(context=context,
                                         token_id=token_id)
            except exception.TokenNotFound:
                raise e

        token_data['access']['token']['id'] = token_id

        return token_data

    def _authenticate_token(self, context, auth):
        """Try to authenticate using an already existing token.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'token' not in auth:
            raise exception.ValidationError(
                attribute='token', target='auth')

        if "id" not in auth['token']:
            raise exception.ValidationError(
                attribute="id", target="token")

        old_token = auth['token']['id']
        if len(old_token) > CONF.max_token_size:
            raise exception.ValidationSizeError(attribute='token',
                                                size=CONF.max_token_size)

        try:
            old_token_ref = self.token_api.get_token(context=context,
                                                     token_id=old_token)
        except exception.NotFound as e:
            raise exception.Unauthorized(e)

        #A trust token cannot be used to get another token
        if 'trust' in old_token_ref:
            raise exception.Forbidden()
        if 'trust_id' in old_token_ref['metadata']:
            raise exception.Forbidden()

        user_ref = old_token_ref['user']
        user_id = user_ref['id']
        if not CONF.trust.enabled and 'trust_id' in auth:
            raise exception.Forbidden('Trusts are disabled.')
        elif CONF.trust.enabled and 'trust_id' in auth:
            trust_ref = self.trust_api.get_trust(context, auth['trust_id'])
            if trust_ref is None:
                raise exception.Forbidden()
            if user_id != trust_ref['trustee_user_id']:
                raise exception.Forbidden()
            if ('expires' in trust_ref) and (trust_ref['expires']):
                expiry = trust_ref['expires']
                if expiry < timeutils.parse_isotime(timeutils.isotime()):
                    raise exception.Forbidden()()
            user_id = trust_ref['trustor_user_id']
            trustor_user_ref = (self.identity_api.get_user(
                                context=context,
                                user_id=trust_ref['trustor_user_id']))
            if not trustor_user_ref['enabled']:
                raise exception.Forbidden()()
            trustee_user_ref = self.identity_api.get_user(
                context, trust_ref['trustee_user_id'])
            if not trustee_user_ref['enabled']:
                raise exception.Forbidden()()
            if trust_ref['impersonation'] == 'True':
                current_user_ref = trustor_user_ref
            else:
                current_user_ref = trustee_user_ref

        else:
            current_user_ref = self.identity_api.get_user(context=context,
                                                          user_id=user_id)

        tenant_id = self._get_project_id_from_auth(context, auth)

        tenant_ref = self._get_project_ref(context, user_id, tenant_id)
        metadata_ref = self._get_metadata_ref(context, user_id, tenant_id)

        # TODO(henry-nash): If no tenant was specified, instead check for a
        # domain and find any related user/group roles

        self._append_roles(metadata_ref,
                           self._get_group_metadata_ref(
                               context, user_id, tenant_id))

        expiry = old_token_ref['expires']
        if CONF.trust.enabled and 'trust_id' in auth:
            trust_id = auth['trust_id']
            trust_roles = []
            for role in trust_ref['roles']:
                if 'roles' not in metadata_ref:
                    raise exception.Forbidden()()
                if role['id'] in metadata_ref['roles']:
                    trust_roles.append(role['id'])
                else:
                    raise exception.Forbidden()
            if 'expiry' in trust_ref and trust_ref['expiry']:
                trust_expiry = timeutils.parse_isotime(trust_ref['expiry'])
                if trust_expiry < expiry:
                    expiry = trust_expiry
            metadata_ref['roles'] = trust_roles
            metadata_ref['trustee_user_id'] = trust_ref['trustee_user_id']
            metadata_ref['trust_id'] = trust_id

        return (current_user_ref, tenant_ref, metadata_ref, expiry)

    def _authenticate_local(self, context, auth):
        """Try to authenticate against the identity backend.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'passwordCredentials' not in auth:
            raise exception.ValidationError(
                attribute='passwordCredentials', target='auth')

        if "password" not in auth['passwordCredentials']:
            raise exception.ValidationError(
                attribute='password', target='passwordCredentials')

        password = auth['passwordCredentials']['password']
        max_pw_size = utils.MAX_PASSWORD_LENGTH
        if password and len(password) > max_pw_size:
            raise exception.ValidationSizeError(attribute='password',
                                                size=max_pw_size)

        if ("userId" not in auth['passwordCredentials'] and
                "username" not in auth['passwordCredentials']):
            raise exception.ValidationError(
                attribute='username or userId',
                target='passwordCredentials')

        user_id = auth['passwordCredentials'].get('userId', None)
        if user_id and len(user_id) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='userId',
                                                size=CONF.max_param_size)

        username = auth['passwordCredentials'].get('username', '')
        if len(username) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='username',
                                                size=CONF.max_param_size)

        if username:
            try:
                user_ref = self.identity_api.get_user_by_name(
                    context=context, user_name=username,
                    domain_id=DEFAULT_DOMAIN_ID)
                user_id = user_ref['id']
            except exception.UserNotFound as e:
                raise exception.Unauthorized(e)

        tenant_id = self._get_project_id_from_auth(context, auth)

        try:
            auth_info = self.identity_api.authenticate(
                context=context,
                user_id=user_id,
                password=password,
                tenant_id=tenant_id)
        except AssertionError as e:
            raise exception.Unauthorized(e)
        (user_ref, tenant_ref, metadata_ref) = auth_info

        # By now we will have authorized and if a tenant/project was
        # specified, we will have obtained its metadata.  In this case
        # we just need to add in any group roles.
        #
        # TODO(henry-nash): If no tenant was specified, instead check for a
        # domain and find any related user/group roles

        self._append_roles(metadata_ref,
                           self._get_group_metadata_ref(
                               context, user_id, tenant_id))

        expiry = core.default_expire_time()
        return (user_ref, tenant_ref, metadata_ref, expiry)

    def _authenticate_external(self, context, auth):
        """Try to authenticate an external user via REMOTE_USER variable.

        Returns auth_token_data, (user_ref, tenant_ref, metadata_ref)
        """
        if 'REMOTE_USER' not in context:
            raise ExternalAuthNotApplicable()

        username = context['REMOTE_USER']
        try:
            user_ref = self.identity_api.get_user_by_name(
                context=context, user_name=username,
                domain_id=DEFAULT_DOMAIN_ID)
            user_id = user_ref['id']
        except exception.UserNotFound as e:
            raise exception.Unauthorized(e)

        tenant_id = self._get_project_id_from_auth(context, auth)

        tenant_ref = self._get_project_ref(context, user_id, tenant_id)
        metadata_ref = self._get_metadata_ref(context, user_id, tenant_id)

        # TODO(henry-nash): If no tenant was specified, instead check for a
        # domain and find any related user/group roles

        self._append_roles(metadata_ref,
                           self._get_group_metadata_ref(
                               context, user_id, tenant_id))

        expiry = core.default_expire_time()
        return (user_ref, tenant_ref, metadata_ref, expiry)

    def _get_auth_token_data(self, user, tenant, metadata, expiry):
        return dict(user=user,
                    tenant=tenant,
                    metadata=metadata,
                    expires=expiry)

    def _get_project_id_from_auth(self, context, auth):
        """Extract tenant information from auth dict.

        Returns a valid tenant_id if it exists, or None if not specified.
        """
        tenant_id = auth.get('tenantId', None)
        if tenant_id and len(tenant_id) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='tenantId',
                                                size=CONF.max_param_size)

        tenant_name = auth.get('tenantName', None)
        if tenant_name and len(tenant_name) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='tenantName',
                                                size=CONF.max_param_size)

        if tenant_name:
            try:
                tenant_ref = self.identity_api.get_project_by_name(
                    context=context, tenant_name=tenant_name,
                    domain_id=DEFAULT_DOMAIN_ID)
                tenant_id = tenant_ref['id']
            except exception.ProjectNotFound as e:
                raise exception.Unauthorized(e)
        return tenant_id

    def _get_domain_id_from_auth(self, context, auth):
        """Extract domain information from v3 auth dict.

        Returns a valid domain_id if it exists, or None if not specified.
        """
        # FIXME(henry-nash): This is a placeholder that needs to be
        # only called in the v3 context, and the auth.get calls
        # converted to the v3 format
        domain_id = auth.get('domainId', None)
        domain_name = auth.get('domainName', None)
        if domain_name:
            try:
                domain_ref = self.identity_api._get_domain_by_name(
                    context=context, domain_name=domain_name)
                domain_id = domain_ref['id']
            except exception.DomainNotFound as e:
                raise exception.Unauthorized(e)
        return domain_id

    def _get_project_ref(self, context, user_id, tenant_id):
        """Returns the tenant_ref for the user's tenant."""
        tenant_ref = None
        if tenant_id:
            tenants = self.identity_api.get_projects_for_user(context, user_id)
            if tenant_id not in tenants:
                msg = 'User %s is unauthorized for tenant %s' % (
                    user_id, tenant_id)
                LOG.warning(msg)
                raise exception.Unauthorized(msg)

            try:
                tenant_ref = self.identity_api.get_project(context=context,
                                                           tenant_id=tenant_id)
            except exception.ProjectNotFound as e:
                exception.Unauthorized(e)
        return tenant_ref

    def _get_metadata_ref(self, context, user_id=None, tenant_id=None,
                          domain_id=None, group_id=None):
        """Returns metadata_ref for a user or group in a tenant or domain."""

        metadata_ref = {}
        if (user_id or group_id) and (tenant_id or domain_id):
            try:
                metadata_ref = self.identity_api.get_metadata(
                    context=context, user_id=user_id, tenant_id=tenant_id,
                    domain_id=domain_id, group_id=group_id)
            except exception.MetadataNotFound:
                pass
        return metadata_ref

    def _get_group_metadata_ref(self, context, user_id,
                                tenant_id=None, domain_id=None):
        """Return any metadata for this project/domain due to group grants."""
        group_refs = self.identity_api.list_groups_for_user(context=context,
                                                            user_id=user_id)
        metadata_ref = {}
        for x in group_refs:
            metadata_ref.update(self._get_metadata_ref(context,
                                                       group_id=x['id'],
                                                       tenant_id=tenant_id,
                                                       domain_id=domain_id))
        return metadata_ref

    def _append_roles(self, metadata, additional_metadata):
        """Add additional roles to the roles in metadata.

        The final set of roles represents the union of existing roles and
        additional roles.
        """

        first = set(metadata.get('roles', []))
        second = set(additional_metadata.get('roles', []))
        metadata['roles'] = list(first.union(second))

    def _get_token_ref(self, context, token_id, belongs_to=None):
        """Returns a token if a valid one exists.

        Optionally, limited to a token owned by a specific tenant.

        """
        data = self.token_api.get_token(context=context,
                                        token_id=token_id)
        if belongs_to:
            if data.get('tenant') is None:
                raise exception.Unauthorized(
                    _('Token does not belong to specified tenant.'))
            if data['tenant'].get('id') != belongs_to:
                raise exception.Unauthorized(
                    _('Token does not belong to specified tenant.'))
        return data

    def _assert_default_domain(self, context, token_ref):
        """Make sure we are operating on default domain only."""
        if token_ref.get('token_data'):
            # this is a V3 token
            msg = _('Non-default domain is not supported')
            # user in a non-default is prohibited
            if (token_ref['token_data']['token']['user']['domain']['id'] !=
                    DEFAULT_DOMAIN_ID):
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
                if project_domain_id != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)
            # if token is scoped to trust, both trustor and trustee must
            # be in the default domain. Furthermore, the delegated project
            # must also be in the default domain
            metadata_ref = token_ref['metadata']
            if CONF.trust.enabled and 'trust_id' in metadata_ref:
                trust_ref = self.trust_api.get_trust(context,
                                                     metadata_ref['trust_id'])
                trustee_user_ref = self.identity_api.get_user(
                    context, trust_ref['trustee_user_id'])
                if trustee_user_ref['domain_id'] != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)
                trustor_user_ref = self.identity_api.get_user(
                    context, trust_ref['trustor_user_id'])
                if trustor_user_ref['domain_id'] != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)
                project_ref = self.identity_api.get_project(
                    context, trust_ref['project_id'])
                if project_ref['domain_id'] != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)

    @controller.protected
    def validate_token_head(self, context, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Identical to ``validate_token``, except does not return a response.

        """
        belongs_to = context['query_string'].get('belongsTo')
        token_ref = self._get_token_ref(context, token_id, belongs_to)
        assert token_ref
        self._assert_default_domain(context, token_ref)

    @controller.protected
    def validate_token(self, context, token_id):
        """Check that a token is valid.

        Optionally, also ensure that it is owned by a specific tenant.

        Returns metadata about the token along any associated roles.

        """
        belongs_to = context['query_string'].get('belongsTo')
        token_ref = self._get_token_ref(context, token_id, belongs_to)
        self._assert_default_domain(context, token_ref)

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        metadata_ref = token_ref['metadata']
        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))

        # Get a service catalog if possible
        # This is needed for on-behalf-of requests
        catalog_ref = None
        if token_ref.get('tenant'):
            catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=token_ref['user']['id'],
                tenant_id=token_ref['tenant']['id'],
                metadata=metadata_ref)
        return Auth.format_token(token_ref, roles_ref, catalog_ref)

    def delete_token(self, context, token_id):
        """Delete a token, effectively invalidating it for authz."""
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)
        self.token_api.delete_token(context=context, token_id=token_id)

    @controller.protected
    def revocation_list(self, context, auth=None):
        tokens = self.token_api.list_revoked_tokens(context)

        for t in tokens:
            expires = t['expires']
            if not (expires and isinstance(expires, unicode)):
                    t['expires'] = timeutils.isotime(expires)
        data = {'revoked': tokens}
        json_data = json.dumps(data)
        signed_text = cms.cms_sign_text(json_data,
                                        CONF.signing.certfile,
                                        CONF.signing.keyfile)

        return {'signed': signed_text}

    def endpoints(self, context, token_id):
        """Return a list of endpoints available to the token."""
        self.assert_admin(context)

        token_ref = self._get_token_ref(context, token_id)

        catalog_ref = None
        if token_ref.get('tenant'):
            catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=token_ref['user']['id'],
                tenant_id=token_ref['tenant']['id'],
                metadata=token_ref['metadata'])

        return Auth.format_endpoint_list(catalog_ref)

    @classmethod
    def format_authenticate(cls, token_ref, roles_ref, catalog_ref):
        o = Auth.format_token(token_ref, roles_ref)
        o['access']['serviceCatalog'] = Auth.format_catalog(catalog_ref)
        return o

    @classmethod
    def format_token(cls, token_ref, roles_ref, catalog_ref=None):
        user_ref = token_ref['user']
        metadata_ref = token_ref['metadata']
        expires = token_ref['expires']
        if expires is not None:
            if not isinstance(expires, unicode):
                expires = timeutils.isotime(expires)
        o = {'access': {'token': {'id': token_ref['id'],
                                  'expires': expires,
                                  'issued_at': timeutils.strtime()
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
        if 'tenant' in token_ref and token_ref['tenant']:
            token_ref['tenant']['enabled'] = True
            o['access']['token']['tenant'] = token_ref['tenant']
        if catalog_ref is not None:
            o['access']['serviceCatalog'] = Auth.format_catalog(catalog_ref)
        if metadata_ref:
            if 'is_admin' in metadata_ref:
                o['access']['metadata'] = {'is_admin':
                                           metadata_ref['is_admin']}
            else:
                o['access']['metadata'] = {'is_admin': 0}
        if 'roles' in metadata_ref:
            o['access']['metadata']['roles'] = metadata_ref['roles']
        if CONF.trust.enabled and 'trust_id' in metadata_ref:
            o['access']['trust'] = {'trustee_user_id':
                                    metadata_ref['trustee_user_id'],
                                    'id': metadata_ref['trust_id']
                                    }
        return o

    @classmethod
    def format_catalog(cls, catalog_ref):
        """Munge catalogs from internal to output format
        Internal catalogs look like:

        {$REGION: {
            {$SERVICE: {
                $key1: $value1,
                ...
                }
            }
        }

        The legacy api wants them to look like

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
        for region, region_ref in catalog_ref.iteritems():
            for service, service_ref in region_ref.iteritems():
                new_service_ref = services.get(service, {})
                new_service_ref['name'] = service_ref.pop('name')
                new_service_ref['type'] = service
                new_service_ref['endpoints_links'] = []
                service_ref['region'] = region

                endpoints_ref = new_service_ref.get('endpoints', [])
                endpoints_ref.append(service_ref)

                new_service_ref['endpoints'] = endpoints_ref
                services[service] = new_service_ref

        return services.values()

    @classmethod
    def format_endpoint_list(cls, catalog_ref):
        """Formats a list of endpoints according to Identity API v2.

        The v2.0 API wants an endpoint list to look like::

            {
                'endpoints': [
                    {
                        'id': $endpoint_id,
                        'name': $SERVICE[name],
                        'type': $SERVICE,
                        'tenantId': $tenant_id,
                        'region': $REGION,
                    }
                ],
                'endpoints_links': [],
            }

        """
        if not catalog_ref:
            return {}

        endpoints = []
        for region_name, region_ref in catalog_ref.iteritems():
            for service_type, service_ref in region_ref.iteritems():
                endpoints.append({
                    'id': service_ref.get('id'),
                    'name': service_ref.get('name'),
                    'type': service_type,
                    'region': region_name,
                    'publicURL': service_ref.get('publicURL'),
                    'internalURL': service_ref.get('internalURL'),
                    'adminURL': service_ref.get('adminURL'),
                })

        return {'endpoints': endpoints, 'endpoints_links': []}

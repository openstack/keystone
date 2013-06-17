# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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

"""Keystone UUID Token Provider"""

from __future__ import absolute_import

import sys
import uuid

from keystone.common import dependency
from keystone.common import logging
from keystone import config
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import token
from keystone import trust


LOG = logging.getLogger(__name__)
CONF = config.CONF
DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id


@dependency.requires('catalog_api', 'identity_api')
class V2TokenDataHelper(object):
    """Creates V2 token data."""
    @classmethod
    def format_token(cls, token_ref, roles_ref, catalog_ref=None):
        user_ref = token_ref['user']
        metadata_ref = token_ref['metadata']
        expires = token_ref.get('expires', token.default_expire_time())
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
    def get_token_data(cls, **kwargs):
        if 'token_ref' not in kwargs:
            raise ValueError('Require token_ref to create V2 token data')
        token_ref = kwargs.get('token_ref')
        roles_ref = kwargs.get('roles_ref', [])
        catalog_ref = kwargs.get('catalog_ref')
        return V2TokenDataHelper.format_token(
            token_ref, roles_ref, catalog_ref)


@dependency.requires('catalog_api', 'identity_api')
class V3TokenDataHelper(object):
    """Token data helper."""
    def __init__(self):
        if CONF.trust.enabled:
            self.trust_api = trust.Manager()

    def _get_filtered_domain(self, domain_id):
        domain_ref = self.identity_api.get_domain(domain_id)
        return {'id': domain_ref['id'], 'name': domain_ref['name']}

    def _get_filtered_project(self, project_id):
        project_ref = self.identity_api.get_project(project_id)
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
            roles = self.identity_api.get_roles_for_user_and_domain(
                user_id, domain_id)
        if project_id:
            roles = self.identity_api.get_roles_for_user_and_project(
                user_id, project_id)
        return [self.identity_api.get_role(role_id) for role_id in roles]

    def _populate_user(self, token_data, user_id, domain_id, project_id,
                       trust):
        if 'user' in token_data:
            # no need to repopulate user if it already exists
            return

        user_ref = self.identity_api.get_user(user_id)
        if CONF.trust.enabled and trust and 'OS-TRUST:trust' not in token_data:
            trustor_user_ref = (self.identity_api.get_user(
                                trust['trustor_user_id']))
            if not trustor_user_ref['enabled']:
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

    def _populate_roles(self, token_data, user_id, domain_id, project_id,
                        trust):
        if 'roles' in token_data:
            # no need to repopulate roles
            return

        if CONF.trust.enabled and trust:
            token_user_id = trust['trustor_user_id']
            token_project_id = trust['project_id']
            #trusts do not support domains yet
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
                            _('Trustee have no delegated roles.'))
            else:
                for role in roles:
                    filtered_roles.append({'id': role['id'],
                                           'name': role['name']})

            # user has no project or domain roles, therefore access denied
            if not filtered_roles:
                if token_project_id:
                    msg = _('User %(user_id)s have no access '
                            'to project %(project_id)s') % {
                                'user_id': user_id,
                                'project_id': token_project_id}
                else:
                    msg = _('User %(user_id)s have no access '
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
            try:
                service_catalog = self.catalog_api.get_v3_catalog(
                    user_id, project_id)
            # TODO(ayoung): KVS backend needs a sample implementation
            except exception.NotImplemented:
                service_catalog = {}
            # TODO(gyee): v3 service catalog is not quite completed yet
            # TODO(ayoung): Enforce Endpoints for trust
            token_data['catalog'] = service_catalog

    def _populate_token_dates(self, token_data, expires=None, trust=None):
        if not expires:
            expires = token.default_expire_time()
        if not isinstance(expires, basestring):
            expires = timeutils.isotime(expires, subsecond=True)
        token_data['expires_at'] = expires
        token_data['issued_at'] = timeutils.isotime(subsecond=True)

    def get_token_data(self, user_id, method_names, extras,
                       domain_id=None, project_id=None, expires=None,
                       trust=None, token=None, include_catalog=True,
                       bind=None):
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
        self._populate_user(token_data, user_id, domain_id, project_id, trust)
        self._populate_roles(token_data, user_id, domain_id, project_id, trust)
        if include_catalog:
            self._populate_service_catalog(token_data, user_id, domain_id,
                                           project_id, trust)
        self._populate_token_dates(token_data, expires=expires, trust=trust)
        return {'token': token_data}


@dependency.requires('token_api', 'identity_api', 'catalog_api')
class Provider(token.provider.Provider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)
        if CONF.trust.enabled:
            self.trust_api = trust.Manager()
        self.v3_token_data_helper = V3TokenDataHelper()
        self.v2_token_data_helper = V2TokenDataHelper()

    def get_token_version(self, token_data):
        if token_data and isinstance(token_data, dict):
            if 'access' in token_data:
                return token.provider.V2
            if 'token' in token_data and 'methods' in token_data['token']:
                return token.provider.V3
        raise token.provider.UnsupportedTokenVersionException()

    def _get_token_id(self, token_data):
        return uuid.uuid4().hex

    def _issue_v2_token(self, **kwargs):
        token_data = self.v2_token_data_helper.get_token_data(**kwargs)
        token_id = self._get_token_id(token_data)
        token_data['access']['token']['id'] = token_id
        try:
            expiry = token_data['access']['token']['expires']
            token_ref = kwargs.get('token_ref')
            if isinstance(expiry, basestring):
                expiry = timeutils.normalize_time(
                    timeutils.parse_isotime(expiry))
            data = dict(key=token_id,
                        id=token_id,
                        expires=expiry,
                        user=token_ref['user'],
                        tenant=token_ref['tenant'],
                        metadata=token_ref['metadata'],
                        token_data=token_data,
                        bind=token_ref.get('bind'),
                        trust_id=token_ref['metadata'].get('trust_id'))
            self.token_api.create_token(token_id, data)
        except Exception:
            exc_info = sys.exc_info()
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self.token_api.get_token(token_id)
            except exception.TokenNotFound:
                raise exc_info[0], exc_info[1], exc_info[2]

        return (token_id, token_data)

    def _issue_v3_token(self, **kwargs):
        user_id = kwargs.get('user_id')
        method_names = kwargs.get('method_names')
        expires_at = kwargs.get('expires_at')
        project_id = kwargs.get('project_id')
        domain_id = kwargs.get('domain_id')
        auth_context = kwargs.get('auth_context')
        trust = kwargs.get('trust')
        metadata_ref = kwargs.get('metadata_ref')
        include_catalog = kwargs.get('include_catalog')
        # for V2, trust is stashed in metadata_ref
        if (CONF.trust.enabled and not trust and metadata_ref and
                'trust_id' in metadata_ref):
            trust = self.trust_api.get_trust(metadata_ref['trust_id'])
        token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            method_names,
            auth_context.get('extras') if auth_context else None,
            domain_id=domain_id,
            project_id=project_id,
            expires=expires_at,
            trust=trust,
            bind=auth_context.get('bind') if auth_context else None,
            include_catalog=include_catalog)

        token_id = self._get_token_id(token_data)
        try:
            expiry = token_data['token']['expires_at']
            if isinstance(expiry, basestring):
                expiry = timeutils.normalize_time(
                    timeutils.parse_isotime(expiry))
            # FIXME(gyee): is there really a need to store roles in metadata?
            role_ids = []
            metadata_ref = kwargs.get('metadata_ref', {})
            if 'project' in token_data['token']:
                # project-scoped token, fill in the v2 token data
                # all we care are the role IDs
                role_ids = [r['id'] for r in token_data['token']['roles']]
                metadata_ref = {'roles': role_ids}
            if trust:
                metadata_ref.setdefault('trust_id', trust['id'])
                metadata_ref.setdefault('trustee_user_id',
                                        trust['trustee_user_id'])
            data = dict(key=token_id,
                        id=token_id,
                        expires=expiry,
                        user=token_data['token']['user'],
                        tenant=token_data['token'].get('project'),
                        metadata=metadata_ref,
                        token_data=token_data,
                        trust_id=trust['id'] if trust else None)
            self.token_api.create_token(token_id, data)
        except Exception:
            exc_info = sys.exc_info()
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self.token_api.get_token(token_id)
            except exception.TokenNotFound:
                raise exc_info[0], exc_info[1], exc_info[2]

        return (token_id, token_data)

    def issue_token(self, version='v3.0', **kwargs):
        if version == token.provider.V3:
            return self._issue_v3_token(**kwargs)
        elif version == token.provider.V2:
            return self._issue_v2_token(**kwargs)
        raise token.provider.UnsupportedTokenVersionException

    def _verify_token(self, token_id, belongs_to=None):
        """Verify the given token and return the token_ref."""
        token_ref = self.token_api.get_token(token_id=token_id)
        assert token_ref
        if belongs_to:
            assert (token_ref['tenant'] and
                    token_ref['tenant']['id'] == belongs_to)
        return token_ref

    def revoke_token(self, token_id):
        self.token_api.delete_token(token_id=token_id)

    def _assert_default_domain(self, token_ref):
        """Make sure we are operating on default domain only."""
        if (token_ref.get('token_data') and
                self.get_token_version(token_ref.get('token_data')) ==
                token.provider.V3):
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
                trust_ref = self.trust_api.get_trust(metadata_ref['trust_id'])
                trustee_user_ref = self.identity_api.get_user(
                    trust_ref['trustee_user_id'])
                if trustee_user_ref['domain_id'] != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)
                trustor_user_ref = self.identity_api.get_user(
                    trust_ref['trustor_user_id'])
                if trustor_user_ref['domain_id'] != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)
                project_ref = self.identity_api.get_project(
                    trust_ref['project_id'])
                if project_ref['domain_id'] != DEFAULT_DOMAIN_ID:
                    raise exception.Unauthorized(msg)

    def _validate_v2_token(self, token_id, belongs_to=None, **kwargs):
        try:
            token_ref = self._verify_token(token_id, belongs_to=belongs_to)
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
            if (not token_data or
                    self.get_token_version(token_data) !=
                    token.provider.V2):
                # token is created by old v2 logic
                metadata_ref = token_ref['metadata']
                role_refs = []
                for role_id in metadata_ref.get('roles', []):
                    role_refs.append(self.identity_api.get_role(role_id))

                # Get a service catalog if possible
                # This is needed for on-behalf-of requests
                catalog_ref = None
                if token_ref.get('tenant'):
                    catalog_ref = self.catalog_api.get_catalog(
                        token_ref['user']['id'],
                        token_ref['tenant']['id'],
                        metadata=metadata_ref)
                token_data = self.v2_token_data_helper.get_token_data(
                    token_ref=token_ref,
                    roles_ref=role_refs,
                    catalog_ref=catalog_ref)
            return token_data
        except AssertionError as e:
            LOG.exception(_('Failed to validate token'))
            raise exception.Unauthorized(e)

    def _validate_v3_token(self, token_id):
        token_ref = self._verify_token(token_id)
        # FIXME(gyee): performance or correctness? Should we return the
        # cached token or reconstruct it? Obviously if we are going with
        # the cached token, any role, project, or domain name changes
        # will not be reflected. One may argue that with PKI tokens,
        # we are essentially doing cached token validation anyway.
        # Lets go with the cached token strategy. Since token
        # management layer is now pluggable, one can always provide
        # their own implementation to suit their needs.
        token_data = token_ref.get('token_data')
        if not token_data or 'token' not in token_data:
            # token ref is created by V2 API
            project_id = None
            project_ref = token_ref.get('tenant')
            if project_ref:
                project_id = project_ref['id']
            token_data = self.v3_token_data_helper.get_token_data(
                token_ref['user']['id'],
                ['password', 'token'],
                {},
                project_id=project_id,
                bind=token_ref.get('bind'),
                expires=token_ref['expires'])
        return token_data

    def validate_token(self, token_id, belongs_to=None, version='v3.0'):
        try:
            if version == token.provider.V3:
                return self._validate_v3_token(token_id)
            elif version == token.provider.V2:
                return self._validate_v2_token(token_id,
                                               belongs_to=belongs_to)
            raise token.provider.UnsupportedTokenVersionException()
        except exception.TokenNotFound as e:
            LOG.exception(_('Failed to verify token'))
            raise exception.Unauthorized(e)

    def check_token(self, token_id, belongs_to=None,
                    version='v3.0', **kwargs):
        try:
            token_ref = self._verify_token(token_id, belongs_to=belongs_to)
            if version == token.provider.V2:
                self._assert_default_domain(token_ref)
        except exception.TokenNotFound as e:
            LOG.exception(_('Failed to verify token'))
            raise exception.Unauthorized(e)

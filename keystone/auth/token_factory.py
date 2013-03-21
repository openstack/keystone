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

"""Token Factory"""

import json
import subprocess
import uuid
import webob

from keystone.common import cms
from keystone.common import logging
from keystone.common import utils
from keystone import catalog
from keystone import config
from keystone import exception
from keystone import identity
from keystone import token as token_module
from keystone import trust
from keystone.openstack.common import jsonutils
from keystone.openstack.common import timeutils


CONF = config.CONF

LOG = logging.getLogger(__name__)


class TokenDataHelper(object):
    """Token data helper."""
    def __init__(self, context):
        self.identity_api = identity.Manager()
        self.catalog_api = catalog.Manager()
        self.trust_api = trust.Manager()
        self.context = context

    def _get_filtered_domain(self, domain_id):
        domain_ref = self.identity_api.get_domain(self.context,
                                                  domain_id)
        return {'id': domain_ref['id'], 'name': domain_ref['name']}

    def _populate_scope(self, token_data, domain_id, project_id):
        if 'domain' in token_data or 'project' in token_data:
            return

        if domain_id:
            token_data['domain'] = self._get_filtered_domain(domain_id)
        if project_id:
            project_ref = self.identity_api.get_project(
                self.context, project_id)
            filtered_project = {
                'id': project_ref['id'],
                'name': project_ref['name']}
            filtered_project['domain'] = self._get_filtered_domain(
                project_ref['domain_id'])
            token_data['project'] = filtered_project

    def _get_project_roles_for_user(self, user_id, project_id):
        roles = self.identity_api.get_roles_for_user_and_project(
            self.context, user_id, project_id)
        roles_ref = []
        for role_id in roles:
            role_ref = self.identity_api.get_role(self.context, role_id)
            role_ref.setdefault('project_id', project_id)
            roles_ref.append(role_ref)
        # user have no project roles, therefore access denied
        if len(roles_ref) == 0:
            msg = _('User have no access to project')
            LOG.debug(msg)
            raise exception.Unauthorized(msg)
        return roles_ref

    def _get_domain_roles_for_user(self, user_id, domain_id):
        roles = self.identity_api.get_roles_for_user_and_domain(
            self.context, user_id, domain_id)
        roles_ref = []
        for role_id in roles:
            role_ref = self.identity_api.get_role(self.context, role_id)
            role_ref.setdefault('domain_id', domain_id)
            roles_ref.append(role_ref)
        # user have no domain roles, therefore access denied
        if len(roles_ref) == 0:
            msg = _('User have no access to domain')
            LOG.debug(msg)
            raise exception.Unauthorized(msg)
        return roles_ref

    def _get_roles_for_user(self, user_id, domain_id, project_id):
        roles = []
        if domain_id:
            roles = self._get_domain_roles_for_user(user_id, domain_id)
        if project_id:
            roles = self._get_project_roles_for_user(user_id, project_id)
        return roles

    def _populate_user(self, token_data, user_id, domain_id, project_id,
                       trust):
        if 'user' in token_data:
            return

        user_ref = self.identity_api.get_user(self.context,
                                              user_id)
        if CONF.trust.enabled and trust:
            trustor_user_ref = (self.identity_api.get_user(self.context,
                                trust['trustor_user_id']))
            if not trustor_user_ref['enabled']:
                raise exception.Forbidden()
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
                        raise exception.Forbidden()
            else:
                for role in roles:
                    filtered_roles.append({'id': role['id'],
                                           'name': role['name']})
            token_data['roles'] = filtered_roles

    def _populate_service_catalog(self, token_data, user_id,
                                  domain_id, project_id, trust):
        if 'catalog' in token_data:
            return

        if CONF.trust.enabled and trust:
            user_id = trust['trustor_user_id']
        if project_id or domain_id:
            try:
                service_catalog = self.catalog_api.get_v3_catalog(
                    self.context, user_id, project_id)
            #TODO KVS backend needs a sample implementation
            except exception.NotImplemented:
                service_catalog = {}
            # TODO(gyee): v3 service catalog is not quite completed yet
            #TODO Enforce Endpoints for trust
            token_data['catalog'] = service_catalog

    def _populate_token(self, token_data, expires=None, trust=None):
        if not expires:
            expires = token_module.default_expire_time()
        if not isinstance(expires, basestring):
            expires = timeutils.isotime(expires, subsecond=True)
        token_data['expires_at'] = expires
        token_data['issued_at'] = timeutils.isotime(subsecond=True)

    def get_token_data(self, user_id, method_names, extras,
                       domain_id=None, project_id=None, expires=None,
                       trust=None, token=None):
        token_data = {'methods': method_names,
                      'extras': extras}

        # We've probably already written these to the token
        for x in ('roles', 'user', 'catalog', 'project', 'domain'):
            if token and x in token:
                token_data[x] = token[x]

        if CONF.trust.enabled and trust:
            if user_id != trust['trustee_user_id']:
                raise exception.Forbidden()

        self._populate_scope(token_data, domain_id, project_id)
        self._populate_user(token_data, user_id, domain_id, project_id, trust)
        self._populate_roles(token_data, user_id, domain_id, project_id, trust)
        self._populate_service_catalog(token_data, user_id, domain_id,
                                       project_id, trust)
        self._populate_token(token_data, expires, trust)
        return {'token': token_data}


def recreate_token_data(context, token_data=None, expires=None,
                        user_ref=None, project_ref=None):
    """ Recreate token from an existing token.

    Repopulate the ephemeral data and return the new token data.

    """
    new_expires = expires
    project_id = None
    user_id = None
    domain_id = None
    methods = ['password', 'token']
    extras = {}

    # NOTE(termie): Let's get some things straight here, because this code
    #               is wrong but tested as such:
    # token_data, if it exists, is going to look like:
    #   {'token': ... the actual token data + a superfluous extras field ...}
    # this data is actually stored in the database in the 'extras' column and
    # then deserialized and added to the token_ref, that already has the
    # the 'expires', 'user_id', and 'id' columns from the db.
    # the 'user' and 'tenant' fields are being added to the
    # token_ref due to being deserialized from the 'extras' column
    #
    # So, how this all looks in the db:
    #   id = some_id
    #   user_id = some_user_id
    #   expires = some_expiration
    #   extras = {'user': {'id': some_used_id},
    #             'tenant': {'id': some_tenant_id},
    #             'token_data': 'token': {'domain': {'id': some_domain_id},
    #                                     'project': {'id': some_project_id},
    #                                     'domain': {'id': some_domain_id},
    #                                     'user': {'id': some_user_id},
    #                                     'roles': [{'id': some_role_id}, ...],
    #                                     'catalog': ...,
    #                                     'expires_at': some_expiry_time,
    #                                     'issued_at': now(),
    #                                     'methods': ['password', 'token'],
    #                                     'extras': { ... empty? ...}
    #
    # TODO(termie): reduce stored token complexity, bug filed at:
    #               https://bugs.launchpad.net/keystone/+bug/1159990
    if token_data:
        # peel the outer layer so its easier to operate
        token = token_data['token']
        domain_id = (token['domain']['id'] if 'domain' in token
                     else None)
        project_id = (token['project']['id'] if 'project' in token
                      else None)
        if not new_expires:
            # support Grizzly-3 to Grizzly-RC1 transition
            # tokens issued in G3 has 'expires' instead of 'expires_at'
            new_expires = token.get('expires_at',
                                    token.get('expires'))
        user_id = token['user']['id']
        methods = token['methods']
        extras = token['extras']
    else:
        token = None
        project_id = project_ref['id'] if project_ref else None
        user_id = user_ref['id']
    token_data_helper = TokenDataHelper(context)
    return token_data_helper.get_token_data(user_id,
                                            methods,
                                            extras,
                                            domain_id,
                                            project_id,
                                            new_expires,
                                            token=token)


def create_token(context, auth_context, auth_info):
    token_data_helper = TokenDataHelper(context)
    (domain_id, project_id, trust) = auth_info.get_scope()
    method_names = list(set(auth_info.get_method_names() +
                            auth_context.get('method_names', [])))
    token_data = token_data_helper.get_token_data(
        auth_context['user_id'],
        method_names,
        auth_context['extras'],
        domain_id,
        project_id,
        auth_context.get('expires_at', None),
        trust)

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
    token_api = token_module.Manager()
    try:
        expiry = token_data['token']['expires_at']
        if isinstance(expiry, basestring):
            expiry = timeutils.normalize_time(timeutils.parse_isotime(expiry))
        role_ids = []
        if 'project' in token_data['token']:
            # project-scoped token, fill in the v2 token data
            # all we care are the role IDs
            role_ids = [role['id'] for role in token_data['token']['roles']]
        metadata_ref = {'roles': role_ids}
        data = dict(key=token_id,
                    id=token_id,
                    expires=expiry,
                    user=token_data['token']['user'],
                    tenant=token_data['token'].get('project'),
                    metadata=metadata_ref,
                    token_data=token_data,
                    trust_id=trust['id'] if trust else None)
        token_api.create_token(context, token_id, data)
    except Exception as e:
        # an identical token may have been created already.
        # if so, return the token_data as it is also identical
        try:
            token_api.get_token(context=context,
                                token_id=token_id)
        except exception.TokenNotFound:
            raise e

    return (token_id, token_data)


def render_token_data_response(token_id, token_data, created=False):
    """ Render token data HTTP response.

    Stash token ID into the X-Auth-Token header.

    """
    headers = [('X-Subject-Token', token_id)]
    headers.append(('Vary', 'X-Auth-Token'))
    headers.append(('Content-Type', 'application/json'))

    if created:
        status = (201, 'Created')
    else:
        status = (200, 'OK')

    body = jsonutils.dumps(token_data, cls=utils.SmarterEncoder)
    return webob.Response(body=body,
                          status='%s %s' % status,
                          headerlist=headers)

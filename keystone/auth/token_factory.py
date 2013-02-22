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
from keystone.openstack.common import jsonutils
from keystone.openstack.common import timeutils


CONF = config.CONF

LOG = logging.getLogger(__name__)


class TokenDataHelper(object):
    """Token data helper."""
    def __init__(self, context):
        self.identity_api = identity.Manager()
        self.catalog_api = catalog.Manager()
        self.context = context

    def _get_filtered_domain(self, domain_id):
        domain_ref = self.identity_api.get_domain(self.context,
                                                  domain_id)
        return {'id': domain_ref['id'], 'name': domain_ref['name']}

    def _populate_scope(self, token_data, domain_id, project_id):
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

    def _populate_user(self, token_data, user_id, domain_id, project_id):
        user_ref = self.identity_api.get_user(self.context,
                                              user_id)
        filtered_user = {
            'id': user_ref['id'],
            'name': user_ref['name'],
            'domain': self._get_filtered_domain(user_ref['domain_id'])}
        token_data['user'] = filtered_user

    def _populate_roles(self, token_data, user_id, domain_id, project_id):
        if domain_id or project_id:
            roles = self._get_roles_for_user(user_id, domain_id, project_id)
            # we only care about id and name
            filtered_roles = []
            for role in roles:
                filtered_roles.append({'id': role['id'], 'name': role['name']})
            token_data['roles'] = filtered_roles

    def _populate_service_catalog(self, token_data, user_id,
                                  domain_id, project_id):
        if project_id or domain_id:
            service_catalog = self.catalog_api.get_v3_catalog(
                self.context, user_id, project_id)
            # TODO(gyee): v3 service catalog is not quite completed yet
            token_data['catalog'] = service_catalog

    def _populate_token(self, token_data, expires=None):
        if not expires:
            expires = token_module.default_expire_time()
        if not isinstance(expires, unicode):
            expires = timeutils.isotime(expires)
        token_data['expires'] = expires
        token_data['issued_at'] = timeutils.strtime()

    def get_token_data(self, user_id, method_names, extras,
                       domain_id=None, project_id=None, expires=None):
        token_data = {'methods': method_names,
                      'extras': extras}
        self._populate_scope(token_data, domain_id, project_id)
        self._populate_user(token_data, user_id, domain_id, project_id)
        self._populate_roles(token_data, user_id, domain_id, project_id)
        self._populate_service_catalog(token_data, user_id, domain_id,
                                       project_id)
        self._populate_token(token_data, expires)
        return token_data


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
    if token_data:
        domain_id = (token_data['domain']['id'] if 'domain' in token_data
                     else None)
        project_id = (token_data['project']['id'] if 'project' in token_data
                      else None)
        if not new_expires:
            new_expires = token_data['expires']
        user_id = token_data['user']['id']
        methods = token_data['methods']
        extras = token_data['extras']
    else:
        project_id = project_ref['id']
        user_id = user_ref['id']
    token_data_helper = TokenDataHelper(context)
    return token_data_helper.get_token_data(user_id,
                                            methods,
                                            extras,
                                            domain_id,
                                            project_id,
                                            new_expires)


def create_token(context, auth_context, auth_info):
    token_data_helper = TokenDataHelper(context)
    (domain_id, project_id) = auth_info.get_scope()
    method_names = list(set(auth_info.get_method_names() +
                            auth_context.get('method_names', [])))
    token_data = token_data_helper.get_token_data(auth_context['user_id'],
                                                  method_names,
                                                  auth_context['extras'],
                                                  domain_id,
                                                  project_id,
                                                  auth_context.get('expires',
                                                                   None))
    if CONF.signing.token_format == 'UUID':
        token_id = uuid.uuid4().hex
    elif CONF.signing.token_format == 'PKI':
        token_id = cms.cms_sign_token(json.dumps(token_data),
                                      CONF.signing.certfile,
                                      CONF.signing.keyfile)
    else:
        raise exception.UnexpectedError(
            'Invalid value for token_format: %s.'
            '  Allowed values are PKI or UUID.' %
            CONF.signing.token_format)
    token_api = token_module.Manager()
    try:
        expiry = token_data['expires']
        if isinstance(expiry, basestring):
            expiry = timeutils.parse_isotime(expiry)
        role_ids = []
        if 'project' in token_data:
            # project-scoped token, fill in the v2 token data
            # all we care are the role IDs
            role_ids = [role['id'] for role in token_data['roles']]
        metadata_ref = {'roles': role_ids}
        data = dict(key=token_id,
                    id=token_id,
                    expires=expiry,
                    user=token_data['user'],
                    tenant=token_data.get('project'),
                    metadata=metadata_ref,
                    token_data=token_data)
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


def render_token_data_response(token_id, token_data):
    """ Render token data HTTP response.

    Stash token ID into the X-Auth-Token header.

    """
    headers = [('X-Subject-Token', token_id)]
    headers.append(('Vary', 'X-Auth-Token'))
    headers.append(('Content-Type', 'application/json'))
    status = (200, 'OK')
    body = jsonutils.dumps(token_data, cls=utils.SmarterEncoder)
    return webob.Response(body=body,
                          status='%s %s' % status,
                          headerlist=headers)

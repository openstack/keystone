# Copyright 2015 Hewlett-Packard
# All Rights Reserved.
#
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

import hashlib

from oslo_config import cfg
from oslo_log import log

from keystone.auth import controllers
from keystone.common import dependency
from keystone.contrib.federation import constants as federation_constants
from keystone.contrib.federation import utils
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'federation_api',
                     'identity_api', 'resource_api')
class TokenlessAuthHelper(object):
    def __init__(self, env):
        """A init class for TokenlessAuthHelper.

        :param env: The HTTP request environment that should contain
            client certificate attributes. These attributes should match
            with what the mapping defines. Or a user cannot be mapped and
            results un-authenticated. The following examples are for the
            attributes that reference to the client certificate's Subject's
            Common Name and Organization:
            SSL_CLIENT_S_DN_CN, SSL_CLIENT_S_DN_O
        :type env: dict
        """

        self.env = env

    def _build_scope_info(self):
        """Build the token request scope based on the headers.

        :returns: scope data
        :rtype: dict
        """
        project_id = self.env.get('HTTP_X_PROJECT_ID')
        project_name = self.env.get('HTTP_X_PROJECT_NAME')
        project_domain_id = self.env.get('HTTP_X_PROJECT_DOMAIN_ID')
        project_domain_name = self.env.get('HTTP_X_PROJECT_DOMAIN_NAME')
        domain_id = self.env.get('HTTP_X_DOMAIN_ID')
        domain_name = self.env.get('HTTP_X_DOMAIN_NAME')

        scope = {}
        if project_id:
            scope['project'] = {'id': project_id}
        elif project_name:
            scope['project'] = {'name': project_name}
            if project_domain_id:
                scope['project']['domain'] = {'id': project_domain_id}
            elif project_domain_name:
                scope['project']['domain'] = {'name': project_domain_name}
            else:
                msg = _('Neither Project Domain ID nor Project Domain Name '
                        'was provided.')
                raise exception.ValidationError(msg)
        elif domain_id:
            scope['domain'] = {'id': domain_id}
        elif domain_name:
            scope['domain'] = {'name': domain_name}
        else:
            raise exception.ValidationError(
                attribute='project or domain',
                target='scope')
        return scope

    def get_scope(self):
        auth = {}
        # NOTE(chioleong): auth methods here are insignificant because
        # we only care about using auth.controllers.AuthInfo
        # to validate the scope information. Therefore,
        # we don't provide any identity.
        auth['scope'] = self._build_scope_info()

        # NOTE(chioleong): we'll let AuthInfo validate the scope for us
        auth_info = controllers.AuthInfo.create({}, auth, scope_only=True)
        return auth_info.get_scope()

    def get_mapped_user(self, project_id=None, domain_id=None):
        """Map client certificate to an existing user.

        If user is ephemeral, there is no validation on the user himself;
        however it will be mapped to a corresponding group(s) and the scope
        of this ephemeral user is the same as what is assigned to the group.

        :param project_id:  Project scope of the mapped user.
        :param domain_id: Domain scope of the mapped user.
        :returns: A dictionary that contains the keys, such as
            user_id, user_name, domain_id, domain_name
        :rtype: dict
        """
        idp_id = self._build_idp_id()
        LOG.debug('The IdP Id %s and protocol Id %s are used to look up '
                  'the mapping.', idp_id, CONF.tokenless_auth.protocol)

        mapped_properties, mapping_id = self.federation_api.evaluate(
            idp_id, CONF.tokenless_auth.protocol, self.env)

        user = mapped_properties.get('user', {})
        user_id = user.get('id')
        user_name = user.get('name')
        user_type = user.get('type')
        if user.get('domain') is not None:
            user_domain_id = user.get('domain').get('id')
            user_domain_name = user.get('domain').get('name')
        else:
            user_domain_id = None
            user_domain_name = None

        # if user is ephemeral type, we don't care if the user exists
        # or not, but just care if the mapped group(s) is valid.
        if user_type == utils.UserType.EPHEMERAL:
            user_ref = {'type': utils.UserType.EPHEMERAL}
            group_ids = mapped_properties['group_ids']
            utils.validate_groups_in_backend(group_ids,
                                             mapping_id,
                                             self.identity_api)
            group_ids.extend(
                utils.transform_to_group_ids(
                    mapped_properties['group_names'], mapping_id,
                    self.identity_api, self.assignment_api))
            roles = self.assignment_api.get_roles_for_groups(group_ids,
                                                             project_id,
                                                             domain_id)
            if roles is not None:
                role_names = [role['name'] for role in roles]
                user_ref['roles'] = role_names
            user_ref['group_ids'] = list(group_ids)
            user_ref[federation_constants.IDENTITY_PROVIDER] = idp_id
            user_ref[federation_constants.PROTOCOL] = (
                CONF.tokenless_auth.protocol)
            return user_ref

        if user_id:
            user_ref = self.identity_api.get_user(user_id)
        elif user_name and (user_domain_name or user_domain_id):
            if user_domain_name:
                user_domain = self.resource_api.get_domain_by_name(
                    user_domain_name)
                self.resource_api.assert_domain_enabled(user_domain['id'],
                                                        user_domain)
                user_domain_id = user_domain['id']
            user_ref = self.identity_api.get_user_by_name(user_name,
                                                          user_domain_id)
        else:
            msg = _('User auth cannot be built due to missing either '
                    'user id, or user name with domain id, or user name '
                    'with domain name.')
            raise exception.ValidationError(msg)
        self.identity_api.assert_user_enabled(
            user_id=user_ref['id'],
            user=user_ref)
        user_ref['type'] = utils.UserType.LOCAL
        return user_ref

    def _build_idp_id(self):
        """Build the IdP name from the given config option issuer_attribute.

        The default issuer attribute SSL_CLIENT_I_DN in the environment is
        built with the following formula -

        base64_idp = sha1(env['SSL_CLIENT_I_DN'])

        :returns: base64_idp like the above example
        :rtype: str
        """
        idp = self.env.get(CONF.tokenless_auth.issuer_attribute)
        if idp is None:
            raise exception.TokenlessAuthConfigError(
                issuer_attribute=CONF.tokenless_auth.issuer_attribute)

        hashed_idp = hashlib.sha256(idp)
        return hashed_idp.hexdigest()

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

from __future__ import absolute_import

import base64
import datetime
import uuid

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six
from six.moves.urllib import parse

from keystone.common import dependency
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.i18n import _
from keystone.models import token_model
from keystone.token.providers import base


LOG = log.getLogger(__name__)
CONF = keystone.conf.CONF


def default_expire_time():
    """Determine when a fresh token should expire.

    Expiration time varies based on configuration (see ``[token] expiration``).

    :returns: a naive UTC datetime.datetime object

    """
    expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
    expires_at = timeutils.utcnow() + expire_delta
    return expires_at.replace(microsecond=0)


def random_urlsafe_str():
    """Generate a random URL-safe string.

    :rtype: six.text_type

    """
    # chop the padding (==) off the end of the encoding to save space
    return base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2].decode('utf-8')


def build_audit_info(parent_audit_id=None):
    """Build the audit data for a token.

    If ``parent_audit_id`` is None, the list will be one element in length
    containing a newly generated audit_id.

    If ``parent_audit_id`` is supplied, the list will be two elements in length
    containing a newly generated audit_id and the ``parent_audit_id``. The
    ``parent_audit_id`` will always be element index 1 in the resulting
    list.

    :param parent_audit_id: the audit of the original token in the chain
    :type parent_audit_id: str
    :returns: Keystone token audit data
    """
    audit_id = random_urlsafe_str()
    if parent_audit_id is not None:
        return [audit_id, parent_audit_id]
    return [audit_id]


@dependency.requires('assignment_api', 'catalog_api', 'federation_api',
                     'identity_api', 'resource_api', 'role_api', 'trust_api',
                     'oauth_api')
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
        if project_ref['domain_id'] is not None:
            filtered_project['domain'] = (
                self._get_filtered_domain(project_ref['domain_id']))
        else:
            # Projects acting as a domain do not have a domain_id attribute
            filtered_project['domain'] = None
        return filtered_project

    def _populate_scope(self, token_data, domain_id, project_id):
        if 'domain' in token_data or 'project' in token_data:
            # scope already exist, no need to populate it again
            return

        if domain_id:
            token_data['domain'] = self._get_filtered_domain(domain_id)
        if project_id:
            token_data['project'] = self._get_filtered_project(project_id)
            project_ref = self.resource_api.get_project(project_id)
            token_data['is_domain'] = project_ref['is_domain']

    def _populate_is_admin_project(self, token_data):
        # TODO(ayoung): Support the ability for a project acting as a domain
        # to be the admin project once the rest of the code for projects
        # acting as domains is merged.  Code will likely be:
        # (r.admin_project_name == None and project['is_domain'] == True
        #  and project['name'] == r.admin_project_domain_name)
        admin_project_name = CONF.resource.admin_project_name
        admin_project_domain_name = CONF.resource.admin_project_domain_name

        if not (admin_project_name and admin_project_domain_name):
            return  # admin project not enabled

        project = token_data['project']

        token_data['is_admin_project'] = (
            project['name'] == admin_project_name and
            project['domain']['name'] == admin_project_domain_name)

    def _get_roles_for_user(self, user_id, domain_id, project_id):
        roles = []
        if domain_id:
            roles = self.assignment_api.get_roles_for_user_and_domain(
                user_id, domain_id)
        if project_id:
            roles = self.assignment_api.get_roles_for_user_and_project(
                user_id, project_id)
        return [self.role_api.get_role(role_id) for role_id in roles]

    def populate_roles_for_federated_user(self, token_data, group_ids,
                                          project_id=None, domain_id=None,
                                          user_id=None):
        """Populate roles basing on provided groups and project/domain.

        Used for federated users with dynamically assigned groups.
        This method does not return anything, yet it modifies token_data in
        place.

        :param token_data: a dictionary used for building token response
        :param group_ids: list of group IDs a user is a member of
        :param project_id: project ID to scope to
        :param domain_id: domain ID to scope to
        :param user_id: user ID

        :raises keystone.exception.Unauthorized: when no roles were found

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
        roles = roles + self._get_roles_for_user(user_id, domain_id,
                                                 project_id)

        # remove duplicates
        roles = [dict(t) for t in set([tuple(d.items()) for d in roles])]

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
            trustee_user_ref = (self.identity_api.get_user(
                                trust['trustee_user_id']))
            try:
                self.resource_api.assert_domain_enabled(
                    trustor_user_ref['domain_id'])
            except AssertionError:
                raise exception.TokenNotFound(_('Trustor domain is disabled.'))
            try:
                self.resource_api.assert_domain_enabled(
                    trustee_user_ref['domain_id'])
            except AssertionError:
                raise exception.TokenNotFound(_('Trustee domain is disabled.'))

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
            'domain': self._get_filtered_domain(user_ref['domain_id']),
            'password_expires_at': user_ref['password_expires_at']}
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
            access_token_ref = self.oauth_api.get_access_token(
                access_token['id']
            )
            authed_role_ids = jsonutils.loads(access_token_ref['role_ids'])
            all_roles = self.role_api.list_roles()
            for role in all_roles:
                for authed_role in authed_role_ids:
                    if authed_role == role['id']:
                        filtered_roles.append({'id': role['id'],
                                               'name': role['name']})
            token_data['roles'] = filtered_roles
            return

        if CONF.trust.enabled and trust:
            # If redelegated_trust_id is set, then we must traverse the
            # trust_chain in order to determine who the original trustor is. We
            # need to do this because the user ID of the original trustor helps
            # us determine scope in the redelegated context.
            if trust.get('redelegated_trust_id'):
                trust_chain = self.trust_api.get_trust_pedigree(trust['id'])
                token_user_id = trust_chain[-1]['trustor_user_id']
            else:
                token_user_id = trust['trustor_user_id']

            token_project_id = trust['project_id']
            # trusts do not support domains yet
            token_domain_id = None
        else:
            token_user_id = user_id
            token_project_id = project_id
            token_domain_id = domain_id

        if token_domain_id or token_project_id:
            filtered_roles = []
            if CONF.trust.enabled and trust:
                # First expand out any roles that were in the trust to include
                # any implied roles, whether global or domain specific
                refs = [{'role_id': role['id']} for role in trust['roles']]
                effective_trust_roles = (
                    self.assignment_api.add_implied_roles(refs))
                # Now get the current role assignments for the trustor,
                # including any domain specific roles.
                assignment_list = self.assignment_api.list_role_assignments(
                    user_id=token_user_id,
                    project_id=token_project_id,
                    effective=True, strip_domain_roles=False)
                current_effective_trustor_roles = (
                    list(set([x['role_id'] for x in assignment_list])))
                # Go through each of the effective trust roles, making sure the
                # trustor still has them, if any have been removed, then we
                # will treat the trust as invalid
                for trust_role in effective_trust_roles:

                    match_roles = [x for x in current_effective_trustor_roles
                                   if x == trust_role['role_id']]
                    if match_roles:
                        role = self.role_api.get_role(match_roles[0])
                        if role['domain_id'] is None:
                            filtered_roles.append(role)
                    else:
                        raise exception.Forbidden(
                            _('Trustee has no delegated roles.'))
            else:
                for role in self._get_roles_for_user(token_user_id,
                                                     token_domain_id,
                                                     token_project_id):
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
            token_data['catalog'] = service_catalog

    def _populate_service_providers(self, token_data):
        if 'service_providers' in token_data:
            return

        service_providers = self.federation_api.get_enabled_service_providers()
        if service_providers:
            token_data['service_providers'] = service_providers

    def _populate_token_dates(self, token_data, expires=None, issued_at=None):
        if not expires:
            expires = default_expire_time()
        if not isinstance(expires, six.string_types):
            expires = utils.isotime(expires, subsecond=True)
        token_data['expires_at'] = expires
        token_data['issued_at'] = (issued_at or
                                   utils.isotime(subsecond=True))

    def _populate_audit_info(self, token_data, audit_info=None):
        if audit_info is None or isinstance(audit_info, six.string_types):
            token_data['audit_ids'] = build_audit_info(audit_info)
        elif isinstance(audit_info, list):
            token_data['audit_ids'] = audit_info
        else:
            msg = (_('Invalid audit info data type: %(data)s (%(type)s)') %
                   {'data': audit_info, 'type': type(audit_info)})
            LOG.error(msg)
            raise exception.UnexpectedError(msg)

    def get_token_data(self, user_id, method_names, domain_id=None,
                       project_id=None, expires=None, trust=None, token=None,
                       include_catalog=True, bind=None, access_token=None,
                       issued_at=None, audit_info=None):
        token_data = {'methods': method_names}

        # We've probably already written these to the token
        if token:
            for x in ('roles', 'user', 'catalog', 'project', 'domain'):
                if x in token:
                    token_data[x] = token[x]

        if bind:
            token_data['bind'] = bind

        self._populate_scope(token_data, domain_id, project_id)
        if token_data.get('project'):
            self._populate_is_admin_project(token_data)
        self._populate_user(token_data, user_id, trust)
        self._populate_roles(token_data, user_id, domain_id, project_id, trust,
                             access_token)
        self._populate_audit_info(token_data, audit_info)

        if include_catalog:
            self._populate_service_catalog(token_data, user_id, domain_id,
                                           project_id, trust)
        self._populate_service_providers(token_data)
        self._populate_token_dates(token_data, expires=expires,
                                   issued_at=issued_at)
        self._populate_oauth_section(token_data, access_token)
        return {'token': token_data}


@dependency.requires('catalog_api', 'identity_api', 'oauth_api',
                     'resource_api', 'role_api', 'trust_api')
class BaseProvider(base.Provider):
    def __init__(self, *args, **kwargs):
        super(BaseProvider, self).__init__(*args, **kwargs)
        self.v3_token_data_helper = V3TokenDataHelper()

    def get_token_version(self, token_data):
        if token_data and isinstance(token_data, dict):
            if 'token_version' in token_data:
                if token_data['token_version'] in token_model.VERSIONS:
                    return token_data['token_version']
            # FIXME(morganfainberg): deprecate the following logic in future
            # revisions. It is better to just specify the token_version in
            # the token_data itself. This way we can support future versions
            # that might have the same fields.
            if 'access' in token_data:
                return token_model.V2
            if 'token' in token_data and 'methods' in token_data['token']:
                return token_model.V3
        raise exception.UnsupportedTokenVersionException()

    def _is_mapped_token(self, auth_context):
        return (federation_constants.IDENTITY_PROVIDER in auth_context and
                federation_constants.PROTOCOL in auth_context)

    def issue_token(self, user_id, method_names, expires_at=None,
                    project_id=None, domain_id=None, auth_context=None,
                    trust=None, include_catalog=True,
                    parent_audit_id=None):
        if auth_context and auth_context.get('bind'):
            # NOTE(lbragstad): Check if the token provider being used actually
            # supports bind authentication methods before proceeding.
            if not self._supports_bind_authentication:
                raise exception.NotImplemented(_(
                    'The configured token provider does not support bind '
                    'authentication.'))

        if CONF.trust.enabled and trust:
            if user_id != trust['trustee_user_id']:
                raise exception.Forbidden(_('User is not a trustee.'))

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

        user_dict = self.identity_api.get_user(user_id)
        user_name = user_dict['name']

        token_data = {
            'user': {
                'id': user_id,
                'name': parse.unquote(user_name),
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
            self.v3_token_data_helper.populate_roles_for_federated_user(
                token_data, group_ids, project_id, domain_id, user_id)

        return token_data

    def _verify_token_ref(self, token_ref):
        """Verify and return the given token_ref."""
        if not token_ref:
            raise exception.Unauthorized(_('Token is absent'))
        return token_ref

    def validate_token(self, token_id):
        user_id = None  # id of the user of the token
        methods = None  # list of methods used to obtain a token
        bind = None  # dictionary of bind methods
        issued_at = None  # time at which the token was issued
        expires_at = None  # time at which the token will expire
        audit_ids = None  # list of audit ids specific to the token
        domain_id = None  # domain scope of the token
        project_id = None  # project scope of the token
        access_token = None  # dictionary containing OAUTH1 information
        trust_ref = None  # dictionary containing trust scope
        token_dict = None  # existing token information
        if self.needs_persistence():
            token_ref = token_id
            token_data = token_ref.get('token_data')
            user_id = token_ref['user_id']
            if not token_data or 'token' not in token_data:
                # NOTE(lbragstad): We should never get here. With the
                # issue_token refactors that landed in Ocata, we should no
                # longer be persisting different types of tokens. Everything is
                # a v3 token, period. If a token needs to be represented in the
                # v2.0 format, it should be translated at the controller layer.
                # This code can be removed when Pike opens for development.
                # The only reason I'm not removing it now is because of the
                # ability for a v2.0 token to be persisted while Newton code is
                # still active in an upgrade to Ocata. Hopefully once a
                # deployer is ready to upgrade to Ocata, there won't be any
                # valid v2.0 formatted tokens in the backend and we can safely
                # remove this case, which will be in Pike.
                methods = ['password', 'token']
                bind = token_ref.get('bind')
                # I have no idea why issued_at and expires_at come from two
                # different places...
                issued_at = (
                    token_ref['token_data']['access']['token']['issued_at']
                )
                expires_at = token_ref['expires']
                audit_ids = token_ref['token_data']['access']['token'].get(
                    'audit_ids'
                )
                project_id = None
                project_ref = token_ref.get('tenant')
                if project_ref:
                    project_id = project_ref['id']
                trust_id = token_ref.get('trust_id')
                if trust_id:
                    trust_ref = self.trust_api.get_trust(trust_id)
            else:
                # NOTE(lbragstad): Otherwise assume we are validating a token
                # that was created using the v3 token API.
                methods = token_data['token']['methods']
                bind = token_data['token'].get('bind')
                issued_at = token_data['token']['issued_at']
                expires_at = token_data['token']['expires_at']
                audit_ids = token_data['token'].get('audit_ids')
                domain_id = token_data['token'].get('domain', {}).get('id')
                project_id = token_data['token'].get('project', {}).get('id')
                access_token = None
                if token_data['token'].get('OS-OAUTH1'):
                    access_token = {
                        'id': token_data['token'].get('OS-OAUTH1', {}).get(
                            'access_token_id'
                        ),
                        'consumer_id': token_data['token'].get(
                            'OS-OAUTH1', {}
                        ).get('consumer_id')
                    }
                trust_ref = None
                trust_id = token_ref.get('trust_id')
                if trust_id:
                    trust_ref = self.trust_api.get_trust(trust_id)
                token_dict = None
                if token_data['token']['user'].get(
                        federation_constants.FEDERATION):
                    token_dict = {'user': token_ref['user']}
        else:
            try:
                (user_id, methods, audit_ids, domain_id, project_id, trust_id,
                    federated_info, access_token_id, issued_at, expires_at) = (
                        self.token_formatter.validate_token(token_id))
            except exception.ValidationError as e:
                raise exception.TokenNotFound(e)

            token_dict = None
            trust_ref = None
            if federated_info:
                # NOTE(lbragstad): We need to rebuild information about the
                # federated token as well as the federated token roles. This is
                # because when we validate a non-persistent token, we don't
                # have a token reference to pull the federated token
                # information out of.  As a result, we have to extract it from
                # the token itself and rebuild the federated context. These
                # private methods currently live in the
                # keystone.token.providers.fernet.Provider() class.
                token_dict = self._rebuild_federated_info(
                    federated_info, user_id
                )
                if project_id or domain_id:
                    self._rebuild_federated_token_roles(
                        token_dict,
                        federated_info,
                        user_id,
                        project_id,
                        domain_id
                    )
            if trust_id:
                trust_ref = self.trust_api.get_trust(trust_id)

            access_token = None
            if access_token_id:
                access_token = self.oauth_api.get_access_token(access_token_id)

        return self.v3_token_data_helper.get_token_data(
            user_id,
            method_names=methods,
            domain_id=domain_id,
            project_id=project_id,
            issued_at=issued_at,
            expires=expires_at,
            trust=trust_ref,
            token=token_dict,
            bind=bind,
            access_token=access_token,
            audit_info=audit_ids)

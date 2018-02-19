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
import itertools
import uuid

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import six
from six.moves.urllib import parse

from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.i18n import _
from keystone.models import token_model
from keystone.token.providers import base


LOG = log.getLogger(__name__)
CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs


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


class V3TokenDataHelper(provider_api.ProviderAPIMixin, object):
    """Token data helper."""

    def __init__(self):
        # Keep __init__ around to ensure dependency injection works.
        super(V3TokenDataHelper, self).__init__()

    def _get_filtered_domain(self, domain_id):
        """Ensure the domain is enabled and return domain id and name.

        :param domain_id: The ID of the domain to validate
        :returns: A dictionary containing two keys, the `id` of the domain and
                  the `name` of the domain.
        """
        domain_ref = PROVIDERS.resource_api.get_domain(domain_id)
        if not domain_ref.get('enabled'):
            msg = _('Unable to validate token because domain %(id)s is '
                    'disabled') % {'id': domain_ref['id']}
            LOG.warning(msg)
            raise exception.DomainNotFound(msg)
        return {'id': domain_ref['id'], 'name': domain_ref['name']}

    def _get_filtered_project(self, project_id):
        """Ensure the project and parent domain is enabled.

        :param project_id: The ID of the project to validate
        :return: A dictionary containing up to three keys, the `id` of the
                 project, the `name` of the project, and the parent `domain`.
        """
        project_ref = PROVIDERS.resource_api.get_project(project_id)
        if not project_ref.get('enabled'):
            msg = _('Unable to validate token because project %(id)s is '
                    'disabled') % {'id': project_ref['id']}
            LOG.warning(msg)
            raise exception.ProjectNotFound(msg)
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

    def _populate_scope(self, token_data, system, domain_id, project_id):
        if 'domain' in token_data or 'project' in token_data:
            # scope already exist, no need to populate it again
            return

        if domain_id:
            token_data['domain'] = self._get_filtered_domain(domain_id)
        elif project_id:
            token_data['project'] = self._get_filtered_project(project_id)
            project_ref = PROVIDERS.resource_api.get_project(project_id)
            token_data['is_domain'] = project_ref['is_domain']
        elif system == 'all':
            # NOTE(lbragstad): This might have to be more elegant in the future
            # if, or when, keystone supports scoping a token to a specific
            # service or region.
            token_data['system'] = {'all': True}

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

    def _get_roles_for_user(self, user_id, system, domain_id, project_id):
        roles = []
        if system:
            group_ids = [
                group['id'] for
                group in PROVIDERS.identity_api.list_groups_for_user(user_id)
            ]
            group_roles = []
            for group_id in group_ids:
                roles = PROVIDERS.assignment_api.list_system_grants_for_group(
                    group_id
                )
                for role in roles:
                    group_roles.append(role)

            user_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
                user_id
            )
            return itertools.chain(group_roles, user_roles)
        if domain_id:
            roles = PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                user_id, domain_id)
        if project_id:
            roles = PROVIDERS.assignment_api.get_roles_for_user_and_project(
                user_id, project_id)
        return [PROVIDERS.role_api.get_role(role_id) for role_id in roles]

    def _get_app_cred_roles(self, app_cred, user_id, domain_id, project_id):
        roles = app_cred['roles']
        token_roles = []
        for role in roles:
            try:
                role_ref = PROVIDERS.assignment_api.get_grant(
                    role['id'], user_id=user_id, domain_id=domain_id,
                    project_id=project_id)
                token_roles.append(role_ref)
            except exception.RoleAssignmentNotFound:
                pass
        return [
            PROVIDERS.role_api.get_role(role['id']) for role in token_roles]

    def populate_roles_for_federated_user(self, token_data, group_ids,
                                          project_id=None, domain_id=None,
                                          user_id=None, system=None):
        """Populate roles basing on provided groups and assignments.

        Used for federated users with dynamically assigned groups.
        This method does not return anything, yet it modifies token_data in
        place.

        :param token_data: a dictionary used for building token response
        :param group_ids: list of group IDs a user is a member of
        :param project_id: project ID to scope to
        :param domain_id: domain ID to scope to
        :param user_id: user ID
        :param system: system scope if applicable

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

        roles = PROVIDERS.assignment_api.get_roles_for_groups(
            group_ids, project_id, domain_id
        )
        roles = roles + self._get_roles_for_user(
            user_id, system, domain_id, project_id
        )

        # NOTE(lbragstad): Remove duplicate role references from a list of
        # roles. It is often suggested that this be done with:
        #
        # roles = [dict(t) for t in set([tuple(d.items()) for d in roles])]
        #
        # But that doesn't actually remove duplicates in all cases and causes
        # transient failures because dictionaries are unordered objects. This
        # means {'id': 1, 'foo': 'bar'} and {'foo': 'bar', 'id': 1} won't
        # actually resolve to a single entity in the above logic since they are
        # both considered unique. By using `in` we're performing a containment
        # check, which also does a deep comparison of the objects, which is
        # what we want.
        unique_roles = []
        for role in roles:
            if role not in unique_roles:
                unique_roles.append(role)

        check_roles(unique_roles, user_id, project_id, domain_id)
        token_data['roles'] = unique_roles

    def _populate_user(self, token_data, user_id, trust):
        if 'user' in token_data:
            # no need to repopulate user if it already exists
            return

        user_ref = PROVIDERS.identity_api.get_user(user_id)
        if CONF.trust.enabled and trust and 'OS-TRUST:trust' not in token_data:
            trustor_user_ref = (PROVIDERS.identity_api.get_user(
                                trust['trustor_user_id']))
            trustee_user_ref = (PROVIDERS.identity_api.get_user(
                                trust['trustee_user_id']))
            try:
                PROVIDERS.resource_api.assert_domain_enabled(
                    trustor_user_ref['domain_id'])
            except AssertionError:
                raise exception.TokenNotFound(_('Trustor domain is disabled.'))
            try:
                PROVIDERS.resource_api.assert_domain_enabled(
                    trustee_user_ref['domain_id'])
            except AssertionError:
                raise exception.TokenNotFound(_('Trustee domain is disabled.'))

            try:
                PROVIDERS.identity_api.assert_user_enabled(
                    trust['trustor_user_id']
                )
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

    def _populate_roles(self, token_data, user_id, system, domain_id,
                        project_id, trust, app_cred_id, access_token):
        if 'roles' in token_data:
            # no need to repopulate roles
            return

        if access_token:
            filtered_roles = []
            access_token_ref = PROVIDERS.oauth_api.get_access_token(
                access_token['id']
            )
            authed_role_ids = jsonutils.loads(access_token_ref['role_ids'])
            all_roles = PROVIDERS.role_api.list_roles()
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
                trust_chain = PROVIDERS.trust_api.get_trust_pedigree(
                    trust['id']
                )
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

        if system or token_domain_id or token_project_id:
            filtered_roles = []
            if CONF.trust.enabled and trust:
                # First expand out any roles that were in the trust to include
                # any implied roles, whether global or domain specific
                refs = [{'role_id': role['id']} for role in trust['roles']]
                effective_trust_roles = (
                    PROVIDERS.assignment_api.add_implied_roles(refs))
                # Now get the current role assignments for the trustor,
                # including any domain specific roles.
                assignments = PROVIDERS.assignment_api.list_role_assignments(
                    user_id=token_user_id,
                    system=system,
                    project_id=token_project_id,
                    effective=True, strip_domain_roles=False)
                current_effective_trustor_roles = (
                    list(set([x['role_id'] for x in assignments])))
                # Go through each of the effective trust roles, making sure the
                # trustor still has them, if any have been removed, then we
                # will treat the trust as invalid
                for trust_role in effective_trust_roles:

                    match_roles = [x for x in current_effective_trustor_roles
                                   if x == trust_role['role_id']]
                    if match_roles:
                        role = PROVIDERS.role_api.get_role(match_roles[0])
                        if role['domain_id'] is None:
                            filtered_roles.append(role)
                    else:
                        raise exception.Forbidden(
                            _('Trustee has no delegated roles.'))
            elif app_cred_id:
                app_cred_api = PROVIDERS.application_credential_api
                app_cred_ref = app_cred_api.get_application_credential(
                    app_cred_id)
                for role in self._get_app_cred_roles(app_cred_ref,
                                                     token_user_id,
                                                     token_domain_id,
                                                     token_project_id):
                    filtered_roles.append({'id': role['id'],
                                           'name': role['name']})
            else:
                for role in self._get_roles_for_user(token_user_id,
                                                     system,
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
                elif token_domain_id:
                    msg = _('User %(user_id)s has no access '
                            'to domain %(domain_id)s') % {
                                'user_id': user_id,
                                'domain_id': token_domain_id}
                elif system:
                    msg = _('User %(user_id)s has no access '
                            'to the system') % {'user_id': user_id}
                LOG.debug(msg)
                raise exception.Unauthorized(msg)

            token_data['roles'] = filtered_roles

    def _populate_service_catalog(self, token_data, user_id, system, domain_id,
                                  project_id, trust):
        if 'catalog' in token_data:
            # no need to repopulate service catalog
            return

        if CONF.trust.enabled and trust:
            user_id = trust['trustor_user_id']

        # NOTE(lbragstad): The catalog API requires a project in order to
        # generate a service catalog, but that appears to be only if there are
        # endpoint -> project relationships. In the event we're dealing with a
        # system_scoped token, we should pass None to the catalog API and just
        # get a catalog anyway.
        if project_id or domain_id or system:
            service_catalog = PROVIDERS.catalog_api.get_v3_catalog(
                user_id, project_id)
            token_data['catalog'] = service_catalog

    def _populate_service_providers(self, token_data):
        if 'service_providers' in token_data:
            return

        service_providers = (
            PROVIDERS.federation_api.get_enabled_service_providers()
        )
        if service_providers:
            token_data['service_providers'] = service_providers

    def _validate_identity_provider(self, token_data):
        federated_info = token_data['user'].get('OS-FEDERATION')
        if federated_info:
            idp_id = federated_info['identity_provider']['id']
            PROVIDERS.federation_api.get_idp(idp_id)

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

    def _populate_app_cred(self, token_data, app_cred_id):
        if app_cred_id:
            app_cred_api = PROVIDERS.application_credential_api
            app_cred = app_cred_api.get_application_credential(app_cred_id)
            restricted = not app_cred['unrestricted']
            token_data['application_credential'] = {}
            token_data['application_credential']['id'] = app_cred['id']
            token_data['application_credential']['name'] = app_cred['name']
            token_data['application_credential']['restricted'] = restricted

    def get_token_data(self, user_id, method_names, system=None,
                       domain_id=None, project_id=None, expires=None,
                       app_cred_id=None, trust=None, token=None,
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

        self._populate_scope(token_data, system, domain_id, project_id)
        if token_data.get('project'):
            self._populate_is_admin_project(token_data)
        self._populate_user(token_data, user_id, trust)
        self._populate_roles(token_data, user_id, system, domain_id,
                             project_id, trust, app_cred_id, access_token)
        self._populate_audit_info(token_data, audit_info)

        if include_catalog:
            self._populate_service_catalog(
                token_data, user_id, system, domain_id, project_id, trust
            )
        self._populate_service_providers(token_data)
        self._validate_identity_provider(token_data)
        self._populate_token_dates(token_data, expires=expires,
                                   issued_at=issued_at)
        self._populate_oauth_section(token_data, access_token)
        self._populate_app_cred(token_data, app_cred_id)
        return {'token': token_data}


class BaseProvider(provider_api.ProviderAPIMixin, base.Provider):
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
                    system=None, project_id=None, domain_id=None,
                    auth_context=None, trust=None, app_cred_id=None,
                    include_catalog=True, parent_audit_id=None):
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
            access_token = PROVIDERS.oauth_api.get_access_token(
                access_token_id
            )

        token_data = self.v3_token_data_helper.get_token_data(
            user_id,
            method_names,
            system=system,
            domain_id=domain_id,
            project_id=project_id,
            expires=expires_at,
            trust=trust,
            app_cred_id=app_cred_id,
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

        user_dict = PROVIDERS.identity_api.get_user(user_id)
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

        # FIXME(lbragstad): This will have to account for system-scoping, too.
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
        if self.needs_persistence():
            token_ref = token_id
            token_data = token_ref.get('token_data')
            user_id = token_ref['user_id']
            methods = token_data['token']['methods']
            bind = token_data['token'].get('bind')
            issued_at = token_data['token']['issued_at']
            expires_at = token_data['token']['expires_at']
            audit_ids = token_data['token'].get('audit_ids')
            system = token_data['token'].get('system', {}).get('all')
            if system:
                system = 'all'
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
                trust_ref = PROVIDERS.trust_api.get_trust(trust_id)
            app_cred_id = token_data['token'].get(
                'application_credential', {}).get('id')
            token_dict = None
            if token_data['token']['user'].get(
                    federation_constants.FEDERATION):
                token_dict = {'user': token_ref['user']}
        else:
            try:
                (user_id, methods, audit_ids, system, domain_id,
                    project_id, trust_id, federated_info, access_token_id,
                    app_cred_id, issued_at, expires_at) = (
                        self.token_formatter.validate_token(token_id))
            except exception.ValidationError as e:
                raise exception.TokenNotFound(e)

            bind = None
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
                trust_ref = PROVIDERS.trust_api.get_trust(trust_id)

            access_token = None
            if access_token_id:
                access_token = PROVIDERS.oauth_api.get_access_token(
                    access_token_id
                )

        return self.v3_token_data_helper.get_token_data(
            user_id,
            method_names=methods,
            system=system,
            domain_id=domain_id,
            project_id=project_id,
            issued_at=issued_at,
            expires=expires_at,
            trust=trust_ref,
            token=token_dict,
            bind=bind,
            access_token=access_token,
            audit_info=audit_ids,
            app_cred_id=app_cred_id)

# Copyright 2018 SUSE Linux GmbH
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

"""Workflow Logic the Application Credential service."""

import base64
import os

from oslo_log import log

from keystone.application_credential import schema
from keystone.common import controller
from keystone.common import provider_api
from keystone.common import utils
from keystone.common import validation
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class ApplicationCredentialV3(controller.V3Controller):
    collection_name = 'application_credentials'
    member_name = 'application_credential'
    _public_parameters = frozenset([
        'id',
        'name',
        'description',
        'expires_at',
        'project_id',
        'roles',
        # secret is only exposed after create, it is not stored
        'secret',
        'links',
        'unrestricted'
    ])

    def _normalize_role_list(self, app_cred_roles):
        roles = []
        for role in app_cred_roles:
            if role.get('id'):
                roles.append(role)
            else:
                roles.append(PROVIDERS.role_api.get_unique_role_by_name(
                    role['name']))
        return roles

    def _generate_secret(self):
        length = 64
        secret = os.urandom(length)
        secret = base64.urlsafe_b64encode(secret)
        secret = secret.rstrip(b'=')
        secret = secret.decode('utf-8')
        return secret

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        path = ('/users/%(user_id)s/application_credentials') % {
            'user_id': ref['user_id']}
        ref.setdefault('links', {})
        ref['links']['self'] = cls.base_url(
            context, path=path) + '/' + ref['id']
        return ref

    @classmethod
    def wrap_member(cls, context, ref):
        cls._add_self_referential_link(context, ref)
        ref = cls.filter_params(ref)
        return {cls.member_name: ref}

    def _check_unrestricted(self, token):
        if 'application_credential' in token.methods:
            if not token.application_credential['unrestricted']:
                action = _("Using method 'application_credential' is not "
                           "allowed for managing additional application "
                           "credentials.")
                raise exception.ForbiddenAction(action=action)

    @controller.protected()
    def create_application_credential(self, request, user_id,
                                      application_credential):
        validation.lazy_validate(schema.application_credential_create,
                                 application_credential)

        token = request.auth_context['token']
        self._check_unrestricted(token)
        if request.context.user_id != user_id:
            action = _("Cannot create an application credential for another "
                       "user")
            raise exception.ForbiddenAction(action=action)
        project_id = request.context.project_id
        app_cred = self._assign_unique_id(application_credential)
        if not app_cred.get('secret'):
            app_cred['secret'] = self._generate_secret()
        app_cred['user_id'] = user_id
        app_cred['project_id'] = project_id
        app_cred['roles'] = self._normalize_role_list(
            app_cred.get('roles', token.roles))
        if app_cred.get('expires_at'):
            app_cred['expires_at'] = utils.parse_expiration_date(
                app_cred['expires_at'])
        app_cred = self._normalize_dict(app_cred)
        app_cred_api = PROVIDERS.application_credential_api
        try:
            ref = app_cred_api.create_application_credential(
                app_cred, initiator=request.audit_initiator
            )
        except exception.RoleAssignmentNotFound as e:
            # Raise a Bad Request, not a Not Found, in accordance with the
            # API-SIG recommendations:
            # https://specs.openstack.org/openstack/api-wg/guidelines/http.html#failure-code-clarifications
            raise exception.ApplicationCredentialValidationError(
                detail=str(e))
        return ApplicationCredentialV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('name')
    def list_application_credentials(self, request, filters, user_id):
        app_cred_api = PROVIDERS.application_credential_api
        hints = ApplicationCredentialV3.build_driver_hints(request, filters)
        refs = app_cred_api.list_application_credentials(user_id, hints=hints)
        return ApplicationCredentialV3.wrap_collection(request.context_dict,
                                                       refs)

    @controller.protected()
    def get_application_credential(self, request, user_id,
                                   application_credential_id):
        ref = PROVIDERS.application_credential_api.get_application_credential(
            application_credential_id)
        return ApplicationCredentialV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_application_credential(self, request, user_id,
                                      application_credential_id):
        token = request.auth_context['token']
        self._check_unrestricted(token)
        PROVIDERS.application_credential_api.delete_application_credential(
            application_credential_id, initiator=request.audit_initiator
        )

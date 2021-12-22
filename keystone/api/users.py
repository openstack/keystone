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

# This file handles all flask-restful resources for /v3/users

import base64
import secrets
import uuid

import flask
import http.client
from oslo_serialization import jsonutils
from werkzeug import exceptions

from keystone.api._shared import json_home_relations
from keystone.application_credential import schema as app_cred_schema
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import utils
from keystone.common import validation
import keystone.conf
from keystone import exception as ks_exception
from keystone.i18n import _
from keystone.identity import schema
from keystone import notifications
from keystone.server import flask as ks_flask


CRED_TYPE_EC2 = 'ec2'
CONF = keystone.conf.CONF
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs

ACCESS_TOKEN_ID_PARAMETER_RELATION = (
    json_home_relations.os_oauth1_parameter_rel_func(
        parameter_name='access_token_id')
)


def _convert_v3_to_ec2_credential(credential):
    # Prior to bug #1259584 fix, blob was stored unserialized
    # but it should be stored as a json string for compatibility
    # with the v3 credentials API.  Fall back to the old behavior
    # for backwards compatibility with existing DB contents
    try:
        blob = jsonutils.loads(credential['blob'])
    except TypeError:
        blob = credential['blob']
    return {'user_id': credential.get('user_id'),
            'tenant_id': credential.get('project_id'),
            'access': blob.get('access'),
            'secret': blob.get('secret'),
            'trust_id': blob.get('trust_id')}


def _format_token_entity(entity):

    formatted_entity = entity.copy()
    access_token_id = formatted_entity['id']
    user_id = formatted_entity.get('authorizing_user_id', '')
    if 'role_ids' in entity:
        formatted_entity.pop('role_ids')
    if 'access_secret' in entity:
        formatted_entity.pop('access_secret')

    url = ('/users/%(user_id)s/OS-OAUTH1/access_tokens/%(access_token_id)s'
           '/roles' % {'user_id': user_id,
                       'access_token_id': access_token_id})

    formatted_entity.setdefault('links', {})
    formatted_entity['links']['roles'] = (ks_flask.base_url(url))

    return formatted_entity


def _check_unrestricted_application_credential(token):
    if 'application_credential' in token.methods:
        if not token.application_credential['unrestricted']:
            action = _("Using method 'application_credential' is not "
                       "allowed for managing additional application "
                       "credentials.")
            raise ks_exception.ForbiddenAction(action=action)


def _build_user_target_enforcement():
    target = {}
    try:
        target['user'] = PROVIDERS.identity_api.get_user(
            flask.request.view_args.get('user_id')
        )
        if flask.request.view_args.get('group_id'):
            target['group'] = PROVIDERS.identity_api.get_group(
                flask.request.view_args.get('group_id')
            )
    except ks_exception.NotFound:  # nosec
        # Defer existence in the event the user doesn't exist, we'll
        # check this later anyway.
        pass

    return target


def _build_enforcer_target_data_owner_and_user_id_match():
    ref = {}
    if flask.request.view_args:
        credential_id = flask.request.view_args.get('credential_id')
        if credential_id is not None:
            hashed_id = utils.hash_access_key(credential_id)
            ref['credential'] = PROVIDERS.credential_api.get_credential(
                hashed_id)
    return ref


def _update_request_user_id_attribute():
    # This method handles a special case in policy enforcement. The application
    # credential API is underneath the user path (e.g.,
    # /v3/users/{user_id}/application_credentials/{application_credential_id}).
    # The RBAC enforcer thinks the user to evaluate for application credential
    # ownership comes from the path, but it should come from the actual
    # application credential reference. By ensuring we pull the user ID from
    # the application credential, we close a loop hole where users could
    # effectively bypass authorization to view or delete any application
    # credential in the system, assuming the attacker knows the application
    # credential ID of another user. So long as the attacker matches the user
    # ID in the request path to the user in the token of the request, they can
    # pass the `rule:owner` policy check. This method protects against that by
    # ensuring we use the application credential user ID and not something
    # determined from the client.
    try:
        app_cred = (
            PROVIDERS.application_credential_api.get_application_credential(
                flask.request.view_args.get('application_credential_id')
            )
        )
        flask.request.view_args['user_id'] = app_cred['user_id']

        # This target isn't really used in the default policy for application
        # credentials, but we return it since we're using this method as a hook
        # to update the flask request variables, which are used later in the
        # keystone RBAC enforcer to populate the policy_dict, which ultimately
        # turns into target attributes.
        return {'user_id': app_cred['user_id']}
    except ks_exception.NotFound:  # nosec
        # Defer existance in the event the application credential doesn't
        # exist, we'll check this later anyway.
        pass


def _format_role_entity(role_id):
    role = PROVIDERS.role_api.get_role(role_id)
    formatted_entity = role.copy()
    if 'description' in role:
        formatted_entity.pop('description')
    if 'enabled' in role:
        formatted_entity.pop('enabled')
    return formatted_entity


class UserResource(ks_flask.ResourceBase):
    collection_key = 'users'
    member_key = 'user'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='identity_api', method='get_user')

    def get(self, user_id=None):
        """Get a user resource or list users.

        GET/HEAD /v3/users
        GET/HEAD /v3/users/{user_id}
        """
        if user_id is not None:
            return self._get_user(user_id)
        return self._list_users()

    def _get_user(self, user_id):
        """Get a user resource.

        GET/HEAD /v3/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:get_user',
            build_target=_build_user_target_enforcement
        )
        ref = PROVIDERS.identity_api.get_user(user_id)
        return self.wrap_member(ref)

    def _list_users(self):
        """List users.

        GET/HEAD /v3/users
        """
        filters = ('domain_id', 'enabled', 'idp_id', 'name', 'protocol_id',
                   'unique_id', 'password_expires_at')
        target = None
        if self.oslo_context.domain_id:
            target = {'domain_id': self.oslo_context.domain_id}
        hints = self.build_driver_hints(filters)
        ENFORCER.enforce_call(
            action='identity:list_users', filters=filters, target_attr=target
        )
        domain = self._get_domain_id_for_list_request()
        if domain is None and self.oslo_context.domain_id:
            domain = self.oslo_context.domain_id
        refs = PROVIDERS.identity_api.list_users(
            domain_scope=domain, hints=hints)

        # If the user making the request used a domain-scoped token, let's make
        # sure we filter out users that are not in that domain. Otherwise, we'd
        # be exposing users in other domains. This if statement is needed in
        # case _get_domain_id_for_list_request() short-circuits due to
        # configuration and protects against information from other domains
        # leaking to people who shouldn't see it.
        if self.oslo_context.domain_id:
            domain_id = self.oslo_context.domain_id
            users = [user for user in refs if user['domain_id'] == domain_id]
        else:
            users = refs

        return self.wrap_collection(users, hints=hints)

    def post(self):
        """Create a user.

        POST /v3/users
        """
        user_data = self.request_body_json.get('user', {})
        target = {'user': user_data}
        ENFORCER.enforce_call(
            action='identity:create_user', target_attr=target
        )
        validation.lazy_validate(schema.user_create, user_data)
        user_data = self._normalize_dict(user_data)
        user_data = self._normalize_domain_id(user_data)
        ref = PROVIDERS.identity_api.create_user(
            user_data,
            initiator=self.audit_initiator)
        return self.wrap_member(ref), http.client.CREATED

    def patch(self, user_id):
        """Update a user.

        PATCH /v3/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:update_user',
            build_target=_build_user_target_enforcement
        )
        PROVIDERS.identity_api.get_user(user_id)
        user_data = self.request_body_json.get('user', {})
        validation.lazy_validate(schema.user_update, user_data)
        self._require_matching_id(user_data)
        ref = PROVIDERS.identity_api.update_user(
            user_id, user_data, initiator=self.audit_initiator)
        return self.wrap_member(ref)

    def delete(self, user_id):
        """Delete a user.

        DELETE /v3/users/{user_id}
        """
        ENFORCER.enforce_call(
            action='identity:delete_user',
            build_target=_build_user_target_enforcement
        )
        PROVIDERS.identity_api.delete_user(user_id)
        return None, http.client.NO_CONTENT


class UserChangePasswordResource(ks_flask.ResourceBase):
    @ks_flask.unenforced_api
    def get(self, user_id):
        # Special case, GET is not allowed.
        raise exceptions.MethodNotAllowed(valid_methods=['POST'])

    @ks_flask.unenforced_api
    def post(self, user_id):
        user_data = self.request_body_json.get('user', {})
        validation.lazy_validate(schema.password_change, user_data)

        try:
            PROVIDERS.identity_api.change_password(
                user_id=user_id,
                original_password=user_data['original_password'],
                new_password=user_data['password'],
                initiator=self.audit_initiator)
        except AssertionError as e:
            raise ks_exception.Unauthorized(
                _('Error when changing user password: %s') % e
            )
        return None, http.client.NO_CONTENT


class UserProjectsResource(ks_flask.ResourceBase):
    collection_key = 'projects'
    member_key = 'project'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='resource_api', method='get_project')

    def get(self, user_id):
        filters = ('domain_id', 'enabled', 'name')
        ENFORCER.enforce_call(action='identity:list_user_projects',
                              filters=filters,
                              build_target=_build_user_target_enforcement)
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.assignment_api.list_projects_for_user(user_id)
        return self.wrap_collection(refs, hints=hints)


class UserGroupsResource(ks_flask.ResourceBase):
    collection_key = 'groups'
    member_key = 'group'
    get_member_from_driver = PROVIDERS.deferred_provider_lookup(
        api='identity_api', method='get_group')

    def get(self, user_id):
        """Get groups for a user.

        GET/HEAD /v3/users/{user_id}/groups
        """
        filters = ('name',)
        hints = self.build_driver_hints(filters)
        ENFORCER.enforce_call(action='identity:list_groups_for_user',
                              build_target=_build_user_target_enforcement,
                              filters=filters)
        refs = PROVIDERS.identity_api.list_groups_for_user(user_id=user_id,
                                                           hints=hints)
        if (self.oslo_context.domain_id):
            filtered_refs = []
            for ref in refs:
                if ref['domain_id'] == self.oslo_context.domain_id:
                    filtered_refs.append(ref)
            refs = filtered_refs
        return self.wrap_collection(refs, hints=hints)


class _UserOSEC2CredBaseResource(ks_flask.ResourceBase):
    collection_key = 'credentials'
    member_key = 'credential'

    @classmethod
    def _add_self_referential_link(cls, ref, collection_name=None):
        # NOTE(morgan): This should be refactored to have an EC2 Cred API with
        # a sane prefix instead of overloading the "_add_self_referential_link"
        # method. This was chosen as it more closely mirrors the pre-flask
        # code (for transition).
        path = '/users/%(user_id)s/credentials/OS-EC2/%(credential_id)s'

        url = ks_flask.base_url(path) % {
            'user_id': ref['user_id'],
            'credential_id': ref['access']}
        ref.setdefault('links', {})
        ref['links']['self'] = url


class UserOSEC2CredentialsResourceListCreate(_UserOSEC2CredBaseResource):
    def get(self, user_id):
        """List EC2 Credentials for user.

        GET/HEAD /v3/users/{user_id}/credentials/OS-EC2
        """
        ENFORCER.enforce_call(action='identity:ec2_list_credentials')
        PROVIDERS.identity_api.get_user(user_id)
        credential_refs = PROVIDERS.credential_api.list_credentials_for_user(
            user_id, type=CRED_TYPE_EC2)
        collection_refs = [
            _convert_v3_to_ec2_credential(cred)
            for cred in credential_refs
        ]
        return self.wrap_collection(collection_refs)

    def post(self, user_id):
        """Create EC2 Credential for user.

        POST /v3/users/{user_id}/credentials/OS-EC2
        """
        target = {}
        target['credential'] = {'user_id': user_id}
        ENFORCER.enforce_call(action='identity:ec2_create_credential',
                              target_attr=target)
        PROVIDERS.identity_api.get_user(user_id)
        tenant_id = self.request_body_json.get('tenant_id')
        PROVIDERS.resource_api.get_project(tenant_id)
        blob = dict(
            access=uuid.uuid4().hex,
            secret=uuid.uuid4().hex,
            trust_id=self.oslo_context.trust_id
        )
        credential_id = utils.hash_access_key(blob['access'])
        cred_data = dict(
            user_id=user_id,
            project_id=tenant_id,
            blob=jsonutils.dumps(blob),
            id=credential_id,
            type=CRED_TYPE_EC2
        )
        PROVIDERS.credential_api.create_credential(credential_id, cred_data)
        ref = _convert_v3_to_ec2_credential(cred_data)
        return self.wrap_member(ref), http.client.CREATED


class UserOSEC2CredentialsResourceGetDelete(_UserOSEC2CredBaseResource):
    @staticmethod
    def _get_cred_data(credential_id):
        cred = PROVIDERS.credential_api.get_credential(credential_id)
        if not cred or cred['type'] != CRED_TYPE_EC2:
            raise ks_exception.Unauthorized(
                message=_('EC2 access key not found.'))
        return _convert_v3_to_ec2_credential(cred)

    def get(self, user_id, credential_id):
        """Get a specific EC2 credential.

        GET/HEAD /users/{user_id}/credentials/OS-EC2/{credential_id}
        """
        func = _build_enforcer_target_data_owner_and_user_id_match
        ENFORCER.enforce_call(
            action='identity:ec2_get_credential',
            build_target=func)
        PROVIDERS.identity_api.get_user(user_id)
        ec2_cred_id = utils.hash_access_key(credential_id)
        cred_data = self._get_cred_data(ec2_cred_id)
        return self.wrap_member(cred_data)

    def delete(self, user_id, credential_id):
        """Delete a specific EC2 credential.

        DELETE /users/{user_id}/credentials/OS-EC2/{credential_id}
        """
        func = _build_enforcer_target_data_owner_and_user_id_match
        ENFORCER.enforce_call(action='identity:ec2_delete_credential',
                              build_target=func)
        PROVIDERS.identity_api.get_user(user_id)
        ec2_cred_id = utils.hash_access_key(credential_id)
        self._get_cred_data(ec2_cred_id)
        PROVIDERS.credential_api.delete_credential(ec2_cred_id)
        return None, http.client.NO_CONTENT


class _OAuth1ResourceBase(ks_flask.ResourceBase):
    collection_key = 'access_tokens'
    member_key = 'access_token'

    @classmethod
    def _add_self_referential_link(cls, ref, collection_name=None):
        # NOTE(morgan): This should be refactored to have an OAuth1 API with
        # a sane prefix instead of overloading the "_add_self_referential_link"
        # method. This was chosen as it more closely mirrors the pre-flask
        # code (for transition).
        ref.setdefault('links', {})
        path = '/users/%(user_id)s/OS-OAUTH1/access_tokens' % {
            'user_id': ref.get('authorizing_user_id', '')
        }
        ref['links']['self'] = ks_flask.base_url(path) + '/' + ref['id']


class OAuth1ListAccessTokensResource(_OAuth1ResourceBase):
    def get(self, user_id):
        """List OAuth1 Access Tokens for user.

        GET /v3/users/{user_id}/OS-OAUTH1/access_tokens
        """
        ENFORCER.enforce_call(action='identity:list_access_tokens')
        if self.oslo_context.is_delegated_auth:
            raise ks_exception.Forbidden(
                _('Cannot list request tokens with a token '
                  'issued via delegation.'))
        refs = PROVIDERS.oauth_api.list_access_tokens(user_id)
        formatted_refs = ([_format_token_entity(x) for x in refs])
        return self.wrap_collection(formatted_refs)


class OAuth1AccessTokenCRUDResource(_OAuth1ResourceBase):
    def get(self, user_id, access_token_id):
        """Get specific access token.

        GET/HEAD /v3/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}
        """
        ENFORCER.enforce_call(action='identity:get_access_token')
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise ks_exception.NotFound()
        access_token = _format_token_entity(access_token)
        return self.wrap_member(access_token)

    def delete(self, user_id, access_token_id):
        """Delete specific access token.

        DELETE /v3/users/{user_id}/OS-OAUTH1/access_tokens/{access_token_id}
        """
        ENFORCER.enforce_call(
            action='identity:ec2_delete_credential',
            build_target=_build_enforcer_target_data_owner_and_user_id_match)
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        reason = (
            'Invalidating the token cache because an access token for '
            'consumer %(consumer_id)s has been deleted. Authorization for '
            'users with OAuth tokens will be recalculated and enforced '
            'accordingly the next time they authenticate or validate a '
            'token.' % {'consumer_id': access_token['consumer_id']}
        )
        notifications.invalidate_token_cache_notification(reason)
        PROVIDERS.oauth_api.delete_access_token(
            user_id, access_token_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class OAuth1AccessTokenRoleListResource(ks_flask.ResourceBase):
    collection_key = 'roles'
    member_key = 'role'

    def get(self, user_id, access_token_id):
        """List roles for a user access token.

        GET/HEAD /v3/users/{user_id}/OS-OAUTH1/access_tokens/
                 {access_token_id}/roles
        """
        ENFORCER.enforce_call(action='identity:list_access_token_roles')
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise ks_exception.NotFound()
        authed_role_ids = access_token['role_ids']
        authed_role_ids = jsonutils.loads(authed_role_ids)
        refs = ([_format_role_entity(x) for x in authed_role_ids])
        return self.wrap_collection(refs)


class OAuth1AccessTokenRoleResource(ks_flask.ResourceBase):
    collection_key = 'roles'
    member_key = 'role'

    def get(self, user_id, access_token_id, role_id):
        """Get role for access token.

        GET/HEAD /v3/users/{user_id}/OS-OAUTH1/access_tokens/
                 {access_token_id}/roles/{role_id}
        """
        ENFORCER.enforce_call(action='identity:get_access_token_role')
        access_token = PROVIDERS.oauth_api.get_access_token(access_token_id)
        if access_token['authorizing_user_id'] != user_id:
            raise ks_exception.Unauthorized(_('User IDs do not match'))
        authed_role_ids = access_token['role_ids']
        authed_role_ids = jsonutils.loads(authed_role_ids)
        for authed_role_id in authed_role_ids:
            if authed_role_id == role_id:
                role = _format_role_entity(role_id)
                return self.wrap_member(role)
        raise ks_exception.RoleNotFound(role_id=role_id)


class UserAppCredListCreateResource(ks_flask.ResourceBase):
    collection_key = 'application_credentials'
    member_key = 'application_credential'
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
        'unrestricted',
        'access_rules'
    ])

    @staticmethod
    def _generate_secret():
        length = 64
        secret = secrets.token_bytes(length)
        secret = base64.urlsafe_b64encode(secret)
        secret = secret.rstrip(b'=')
        secret = secret.decode('utf-8')
        return secret

    @staticmethod
    def _normalize_role_list(app_cred_roles):
        roles = []
        for role in app_cred_roles:
            if role.get('id'):
                roles.append(role)
            else:
                roles.append(PROVIDERS.role_api.get_unique_role_by_name(
                    role['name']))
        return roles

    def _get_roles(self, app_cred_data, token):
        if app_cred_data.get('roles'):
            roles = self._normalize_role_list(app_cred_data['roles'])
            # NOTE(cmurphy): The user is not allowed to add a role that is not
            # in their token. This is to prevent trustees or application
            # credential users from escallating their privileges to include
            # additional roles that the trustor or application credential
            # creator has assigned on the project.
            token_roles = [r['id'] for r in token.roles]
            for role in roles:
                if role['id'] not in token_roles:
                    detail = _('Cannot create an application credential with '
                               'unassigned role')
                    raise ks_exception.ApplicationCredentialValidationError(
                        detail=detail)
        else:
            roles = token.roles
        return roles

    def get(self, user_id):
        """List application credentials for user.

        GET/HEAD /v3/users/{user_id}/application_credentials
        """
        filters = ('name',)
        ENFORCER.enforce_call(action='identity:list_application_credentials',
                              filters=filters)
        app_cred_api = PROVIDERS.application_credential_api
        hints = self.build_driver_hints(filters)
        refs = app_cred_api.list_application_credentials(user_id, hints=hints)
        return self.wrap_collection(refs, hints=hints)

    def post(self, user_id):
        """Create application credential.

        POST /v3/users/{user_id}/application_credentials
        """
        ENFORCER.enforce_call(action='identity:create_application_credential')
        app_cred_data = self.request_body_json.get(
            'application_credential', {})
        validation.lazy_validate(app_cred_schema.application_credential_create,
                                 app_cred_data)
        token = self.auth_context['token']
        _check_unrestricted_application_credential(token)
        if self.oslo_context.user_id != user_id:
            action = _('Cannot create an application credential for another '
                       'user.')
            raise ks_exception.ForbiddenAction(action=action)
        project_id = self.oslo_context.project_id
        app_cred_data = self._assign_unique_id(app_cred_data)
        if not app_cred_data.get('secret'):
            app_cred_data['secret'] = self._generate_secret()
        app_cred_data['user_id'] = user_id
        app_cred_data['project_id'] = project_id
        app_cred_data['roles'] = self._get_roles(app_cred_data, token)
        if app_cred_data.get('expires_at'):
            app_cred_data['expires_at'] = utils.parse_expiration_date(
                app_cred_data['expires_at'])
        if app_cred_data.get('access_rules'):
            for access_rule in app_cred_data['access_rules']:
                # If user provides an access rule by ID, it will be looked up
                # by ID. If user provides an access rule that is identical to
                # an existing one, the ID generated here will be ignored and
                # the pre-existing access rule will be used.
                if 'id' not in access_rule:
                    # Generate directly, rather than using _assign_unique_id,
                    # so that there is no deep copy made
                    access_rule['id'] = uuid.uuid4().hex
        app_cred_data = self._normalize_dict(app_cred_data)
        app_cred_api = PROVIDERS.application_credential_api

        try:
            ref = app_cred_api.create_application_credential(
                app_cred_data, initiator=self.audit_initiator)
        except ks_exception.RoleAssignmentNotFound as e:
            # Raise a Bad Request, not a Not Found, in accordance with the
            # API-SIG recommendations:
            # https://specs.openstack.org/openstack/api-wg/guidelines/http.html#failure-code-clarifications
            raise ks_exception.ApplicationCredentialValidationError(
                detail=str(e))
        return self.wrap_member(ref), http.client.CREATED


class UserAppCredGetDeleteResource(ks_flask.ResourceBase):
    collection_key = 'application_credentials'
    member_key = 'application_credential'

    def get(self, user_id, application_credential_id):
        """Get application credential resource.

        GET/HEAD /v3/users/{user_id}/application_credentials/
                 {application_credential_id}
        """
        target = _update_request_user_id_attribute()
        ENFORCER.enforce_call(
            action='identity:get_application_credential',
            target_attr=target,
        )
        ref = PROVIDERS.application_credential_api.get_application_credential(
            application_credential_id)
        return self.wrap_member(ref)

    def delete(self, user_id, application_credential_id):
        """Delete application credential resource.

        DELETE /v3/users/{user_id}/application_credentials/
               {application_credential_id}
        """
        target = _update_request_user_id_attribute()
        ENFORCER.enforce_call(
            action='identity:delete_application_credential',
            target_attr=target
        )
        token = self.auth_context['token']
        _check_unrestricted_application_credential(token)
        PROVIDERS.application_credential_api.delete_application_credential(
            application_credential_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class UserAccessRuleListResource(ks_flask.ResourceBase):
    collection_key = 'access_rules'
    member_key = 'access_rule'

    def get(self, user_id):
        """List access rules for user.

        GET/HEAD /v3/users/{user_id}/access_rules
        """
        filters = ('service', 'path', 'method',)
        ENFORCER.enforce_call(action='identity:list_access_rules',
                              filters=filters,
                              build_target=_build_user_target_enforcement)
        app_cred_api = PROVIDERS.application_credential_api
        hints = self.build_driver_hints(filters)
        refs = app_cred_api.list_access_rules_for_user(user_id, hints=hints)
        hints = self.build_driver_hints(filters)
        return self.wrap_collection(refs, hints=hints)


class UserAccessRuleGetDeleteResource(ks_flask.ResourceBase):
    collection_key = 'access_rules'
    member_key = 'access_rule'

    def get(self, user_id, access_rule_id):
        """Get access rule resource.

        GET/HEAD /v3/users/{user_id}/access_rules/{access_rule_id}
        """
        ENFORCER.enforce_call(
            action='identity:get_access_rule',
            build_target=_build_user_target_enforcement
        )
        ref = PROVIDERS.application_credential_api.get_access_rule(
            access_rule_id)
        return self.wrap_member(ref)

    def delete(self, user_id, access_rule_id):
        """Delete access rule resource.

        DELETE /v3/users/{user_id}/access_rules/{access_rule_id}
        """
        ENFORCER.enforce_call(
            action='identity:delete_access_rule',
            build_target=_build_user_target_enforcement
        )
        PROVIDERS.application_credential_api.delete_access_rule(
            access_rule_id, initiator=self.audit_initiator)
        return None, http.client.NO_CONTENT


class UserAPI(ks_flask.APIBase):
    _name = 'users'
    _import_name = __name__
    resources = [UserResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=UserChangePasswordResource,
            url='/users/<string:user_id>/password',
            resource_kwargs={},
            rel='user_change_password',
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserGroupsResource,
            url='/users/<string:user_id>/groups',
            resource_kwargs={},
            rel='user_groups',
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserProjectsResource,
            url='/users/<string:user_id>/projects',
            resource_kwargs={},
            rel='user_projects',
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserOSEC2CredentialsResourceListCreate,
            url='/users/<string:user_id>/credentials/OS-EC2',
            resource_kwargs={},
            rel='user_credentials',
            resource_relation_func=(
                json_home_relations.os_ec2_resource_rel_func),
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserOSEC2CredentialsResourceGetDelete,
            url=('/users/<string:user_id>/credentials/OS-EC2/'
                 '<string:credential_id>'),
            resource_kwargs={},
            rel='user_credential',
            resource_relation_func=(
                json_home_relations.os_ec2_resource_rel_func),
            path_vars={
                'credential_id': json_home.build_v3_parameter_relation(
                    'credential_id'),
                'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=OAuth1ListAccessTokensResource,
            url='/users/<string:user_id>/OS-OAUTH1/access_tokens',
            resource_kwargs={},
            rel='user_access_tokens',
            resource_relation_func=(
                json_home_relations.os_oauth1_resource_rel_func),
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=OAuth1AccessTokenCRUDResource,
            url=('/users/<string:user_id>/OS-OAUTH1/'
                 'access_tokens/<string:access_token_id>'),
            resource_kwargs={},
            rel='user_access_token',
            resource_relation_func=(
                json_home_relations.os_oauth1_resource_rel_func),
            path_vars={
                'access_token_id': ACCESS_TOKEN_ID_PARAMETER_RELATION,
                'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=OAuth1AccessTokenRoleListResource,
            url=('/users/<string:user_id>/OS-OAUTH1/access_tokens/'
                 '<string:access_token_id>/roles'),
            resource_kwargs={},
            rel='user_access_token_roles',
            resource_relation_func=(
                json_home_relations.os_oauth1_resource_rel_func),
            path_vars={'access_token_id': ACCESS_TOKEN_ID_PARAMETER_RELATION,
                       'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=OAuth1AccessTokenRoleResource,
            url=('/users/<string:user_id>/OS-OAUTH1/access_tokens/'
                 '<string:access_token_id>/roles/<string:role_id>'),
            resource_kwargs={},
            rel='user_access_token_role',
            resource_relation_func=(
                json_home_relations.os_oauth1_resource_rel_func),
            path_vars={'access_token_id': ACCESS_TOKEN_ID_PARAMETER_RELATION,
                       'role_id': json_home.Parameters.ROLE_ID,
                       'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserAppCredListCreateResource,
            url='/users/<string:user_id>/application_credentials',
            resource_kwargs={},
            rel='application_credentials',
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserAppCredGetDeleteResource,
            url=('/users/<string:user_id>/application_credentials/'
                 '<string:application_credential_id>'),
            resource_kwargs={},
            rel='application_credential',
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
                'application_credential_id':
                    json_home.Parameters.APPLICATION_CRED_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserAccessRuleListResource,
            url='/users/<string:user_id>/access_rules',
            resource_kwargs={},
            rel='access_rules',
            path_vars={'user_id': json_home.Parameters.USER_ID}
        ),
        ks_flask.construct_resource_map(
            resource=UserAccessRuleGetDeleteResource,
            url=('/users/<string:user_id>/access_rules/'
                 '<string:access_rule_id>'),
            resource_kwargs={},
            rel='access_rule',
            path_vars={
                'user_id': json_home.Parameters.USER_ID,
                'access_rule_id':
                    json_home.Parameters.ACCESS_RULE_ID}
        )
    ]


APIs = (UserAPI,)

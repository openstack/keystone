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

# This file handles all flask-restful resources for /v3/OS-TRUST

# TODO(morgan): Deprecate /v3/OS-TRUST/trusts path in favour of /v3/trusts.
# /v3/OS-TRUST should remain indefinitely.

import functools

import flask
import flask_restful
from six.moves import http_client

from keystone import assignment
from keystone.common import context
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import utils
from keystone.common import validation
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask
from keystone.trust import schema


ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs

_build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-TRUST',
    extension_version='1.0')
_build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation, extension_name='OS-TRUST',
    extension_version='1.0')

TRUST_ID_PARAMETER_RELATION = _build_parameter_relation(
    parameter_name='trust_id')


def _trustor_trustee_only(trust):
    user_id = flask.request.environ.get(context.REQUEST_CONTEXT_ENV).user_id
    if user_id not in [trust.get('trustee_user_id'),
                       trust.get('trustor_user_id')]:
        raise exception.ForbiddenAction(
            action=_('Requested user has no relation to this trust'))


def _normalize_trust_expires_at(trust):
    # correct isotime
    if trust.get('expires_at') is not None:
        trust['expires_at'] = utils.isotime(trust['expires_at'],
                                            subsecond=True)


def _normalize_trust_roles(trust):
    # fill in role data
    trust_full_roles = []
    for trust_role in trust.get('roles', []):
        trust_role = trust_role['id']
        try:
            matching_role = PROVIDERS.role_api.get_role(trust_role)
            # TODO(morgan): Correct the cross-subsystem call here to allow
            # for local handling of the role wrapping
            full_role = assignment.controllers.RoleV3.wrap_member(
                {'environment': flask.request.environ},
                matching_role)['role']
            trust_full_roles.append(full_role)
        except exception.RoleNotFound:
            pass

    trust['roles'] = trust_full_roles
    trust['roles_links'] = {
        'self': ks_flask.base_url() + '/%s/roles' % trust['id'],
        'next': None,
        'previous': None}


class TrustResource(ks_flask.ResourceBase):
    collection_key = 'trusts'
    member_key = 'trust'
    api_prefix = '/OS-TRUST'
    json_home_resource_rel_func = _build_resource_relation
    json_home_parameter_rel_func = _build_parameter_relation

    def _check_unrestricted(self):
        token = self.auth_context['token']
        if 'application_credential' in token.methods:
            if not token.application_credential['unrestricted']:
                action = _("Using method 'application_credential' is not "
                           "allowed for managing trusts.")
                raise exception.ForbiddenAction(action=action)

    def _find_redelegated_trust(self):
        # Check if delegated via trust
        redelegated_trust = None
        if self.oslo_context.is_delegated_auth:
            src_trust_id = self.oslo_context.trust_id
            if not src_trust_id:
                action = _('Redelegation allowed for delegated by trust only')
                raise exception.ForbiddenAction(action=action)
            redelegated_trust = PROVIDERS.trust_api.get_trust(src_trust_id)
        return redelegated_trust

    @staticmethod
    def _parse_expiration_date(expiration_date):
        if expiration_date is not None:
            return utils.parse_expiration_date(expiration_date)
        return None

    def _require_trustor_has_role_in_project(self, trust):
        trustor_roles = self._get_trustor_roles(trust)
        for trust_role in trust['roles']:
            matching_roles = [x for x in trustor_roles
                              if x == trust_role['id']]
            if not matching_roles:
                raise exception.RoleNotFound(role_id=trust_role['id'])

    def _get_trustor_roles(self, trust):
        original_trust = trust.copy()
        while original_trust.get('redelegated_trust_id'):
            original_trust = PROVIDERS.trust_api.get_trust(
                original_trust['redelegated_trust_id'])

        if not ((trust.get('project_id')) in [None, '']):
            # Check project exists.
            PROVIDERS.resource_api.get_project(trust['project_id'])
            # Get a list of roles including any domain specific roles
            assignment_list = PROVIDERS.assignment_api.list_role_assignments(
                user_id=original_trust['trustor_user_id'],
                project_id=original_trust['project_id'],
                effective=True, strip_domain_roles=False)
            return list({x['role_id'] for x in assignment_list})
        else:
            return []

    def _normalize_role_list(self, trust_roles):
        roles = []
        for role in trust_roles:
            if role.get('id'):
                roles.append({'id': role['id']})
            else:
                roles.append(
                    PROVIDERS.role_api.get_unique_role_by_name(role['name']))
        return roles

    def _get_trust(self, trust_id):
        ENFORCER.enforce_call(action='identity:get_trust')
        trust = PROVIDERS.trust_api.get_trust(trust_id)
        _trustor_trustee_only(trust)
        _normalize_trust_expires_at(trust)
        _normalize_trust_roles(trust)
        return self.wrap_member(trust)

    def _list_trusts(self):
        ENFORCER.enforce_call(action='identity:list_trusts')
        trusts = []
        trustor_user_id = flask.request.args.get('trustor_user_id')
        trustee_user_id = flask.request.args.get('trustee_user_id')

        if not flask.request.args:
            # NOTE(morgan): Admin can list all trusts.
            ENFORCER.enforce_call(action='admin_required')
            trusts += PROVIDERS.trust_api.list_trusts()

        # TODO(morgan): Convert the trustor/trustee checks into policy
        # checkstr we can enforce on. This is duplication of code
        # behavior/design as the OS-TRUST controller for ease of review/
        # comparison of previous code. Minor optimizations [checks before db
        # hits] have been done.
        action = _('Cannot list trusts for another user')
        if trustor_user_id:
            if trustor_user_id != self.oslo_context.user_id:
                raise exception.Forbidden(action=action)

        if trustee_user_id:
            if trustee_user_id != self.oslo_context.user_id:
                raise exception.Forbidden(action=action)

        trusts += PROVIDERS.trust_api.list_trusts_for_trustor(trustor_user_id)
        trusts += PROVIDERS.trust_api.list_trusts_for_trustee(trustee_user_id)

        for trust in trusts:
            # get_trust returns roles, list_trusts does not
            # It seems in some circumstances, roles does not
            # exist in the query response, so check first
            if 'roles' in trust:
                del trust['roles']

            if trust.get('expires_at') is not None:
                trust['expires_at'] = utils.isotime(trust['expires_at'],
                                                    subsecond=True)

        return self.wrap_collection(trusts)

    def get(self, trust_id=None):
        """Dispatch for GET/HEAD or LIST trusts."""
        if trust_id is not None:
            return self._get_trust(trust_id=trust_id)
        else:
            return self._list_trusts()

    def post(self):
        """Create a new trust.

        The User creating the trust must be the trustor.
        """
        ENFORCER.enforce_call(action='identity:create_trust')
        trust = flask.request.json.get('trust', {})
        validation.lazy_validate(schema.trust_create, trust)
        self._check_unrestricted()

        if trust.get('project_id') and not trust.get('roles'):
            action = _('At least one role should be specified')
            raise exception.ForbiddenAction(action=action)

        if self.oslo_context.user_id != trust.get('trustor_user_id'):
            action = _("The authenticated user should match the trustor")
            raise exception.ForbiddenAction(action=action)

        # Ensure the trustee exists
        PROVIDERS.identity_api.get_user(trust['trustee_user_id'])

        # Normalize roles
        trust['roles'] = self._normalize_role_list(trust.get('roles', []))
        self._require_trustor_has_role_in_project(trust)
        trust['expires_at'] = self._parse_expiration_date(
            trust.get('expires_at'))
        trust = self._assign_unique_id(trust)
        redelegated_trust = self._find_redelegated_trust()
        return_trust = PROVIDERS.trust_api.create_trust(
            trust_id=trust['id'],
            trust=trust,
            roles=trust['roles'],
            redelegated_trust=redelegated_trust,
            initiator=self.audit_initiator)
        _normalize_trust_expires_at(return_trust)
        _normalize_trust_roles(return_trust)
        return self.wrap_member(return_trust), http_client.CREATED

    def delete(self, trust_id):
        ENFORCER.enforce_call(action='identity:delete_trust')
        self._check_unrestricted()

        trust = PROVIDERS.trust_api.get_trust(trust_id)

        # TODO(morgan): convert this check to an oslo_policy checkstr that
        # can be referenced/enforced on.
        if (self.oslo_context.user_id != trust.get('trustor_user_id') and
                not self.oslo_context.is_admin):
            action = _('Only admin or trustor can delete a trust')
            raise exception.ForbiddenAction(action=action)

        PROVIDERS.trust_api.delete_trust(trust_id,
                                         initiator=self.audit_initiator)
        return '', http_client.NO_CONTENT


# NOTE(morgan): Since this Resource is not being used with the automatic
# URL additions and does not have a collection key/member_key, we use
# the flask-restful Resource, not the keystone ResourceBase
class RolesForTrustListResource(flask_restful.Resource):
    def get(self, trust_id):
        ENFORCER.enforce_call(action='identity:list_roles_for_trust')
        # NOTE(morgan): This duplicates a little of the .get_trust from the
        # main resource, as it needs some of the same logic. However, due to
        # how flask-restful works, this should be fully encapsulated
        trust = PROVIDERS.trust_api.get_trust(trust_id)
        _trustor_trustee_only(trust)
        _normalize_trust_expires_at(trust)
        _normalize_trust_roles(trust)
        return {'roles': trust['roles'],
                'links': trust['roles_links']}


# NOTE(morgan): Since this Resource is not being used with the automatic
# URL additions and does not have a collection key/member_key, we use
# the flask-restful Resource, not the keystone ResourceBase
class RoleForTrustResource(flask_restful.Resource):
    def get(self, trust_id, role_id):
        """Get a role that has been assigned to a trust."""
        ENFORCER.enforce_call(action='identity:get_role_for_trust')
        trust = PROVIDERS.trust_api.get_trust(trust_id)
        _trustor_trustee_only(trust)
        if not any(role['id'] == role_id for role in trust['roles']):
            raise exception.RoleNotFound(role_id=role_id)

        role = PROVIDERS.role_api.get_role(role_id)
        # TODO(morgan): Correct this to allow for local member wrapping of
        # RoleV3.
        return assignment.controllers.RoleV3.wrap_member(
            {'environment': flask.request.environ}, role)


class TrustAPI(ks_flask.APIBase):
    _name = 'trusts'
    _import_name = __name__
    resources = [TrustResource]
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=RolesForTrustListResource,
            url='/trusts/<string:trust_id>/roles',
            resource_kwargs={},
            rel='trust_roles',
            path_vars={
                'trust_id': TRUST_ID_PARAMETER_RELATION},
            resource_relation_func=_build_resource_relation),
        ks_flask.construct_resource_map(
            resource=RoleForTrustResource,
            url='/trusts/<string:trust_id>/roles/<string:role_id>',
            resource_kwargs={},
            rel='trust_role',
            path_vars={
                'trust_id': TRUST_ID_PARAMETER_RELATION,
                'role_id': json_home.Parameters.ROLE_ID},
            resource_relation_func=_build_resource_relation),
    ]
    _api_url_prefix = '/OS-TRUST'


APIs = (TrustAPI,)

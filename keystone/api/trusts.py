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

import flask
import flask_restful
import http.client
from oslo_log import log
from oslo_policy import _checks as op_checks

from keystone.api._shared import json_home_relations
from keystone.common import context
from keystone.common import json_home
from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common.rbac_enforcer import policy
from keystone.common import utils
from keystone.common import validation
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask
from keystone.trust import schema


LOG = log.getLogger(__name__)
ENFORCER = rbac_enforcer.RBACEnforcer
PROVIDERS = provider_api.ProviderAPIs

_build_resource_relation = json_home_relations.os_trust_resource_rel_func
_build_parameter_relation = json_home_relations.os_trust_parameter_rel_func

TRUST_ID_PARAMETER_RELATION = _build_parameter_relation(
    parameter_name='trust_id')


def _build_trust_target_enforcement():
    target = {}
    # NOTE(cmurphy) unlike other APIs, in the event the trust doesn't exist or
    # has 0 remaining uses, we actually do expect it to return a 404 and not a
    # 403, so don't catch NotFound here (lp#1840288)
    target['trust'] = PROVIDERS.trust_api.get_trust(
        flask.request.view_args.get('trust_id')
    )

    return target


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
            full_role = ks_flask.ResourceBase.wrap_member(
                matching_role, collection_name='roles', member_name='role')
            trust_full_roles.append(full_role['role'])
        except exception.RoleNotFound:
            pass

    trust['roles'] = trust_full_roles
    trust['roles_links'] = {
        'self': ks_flask.base_url(path='/%s/roles' % trust['id']),
        'next': None,
        'previous': None}


class TrustResource(ks_flask.ResourceBase):
    collection_key = 'trusts'
    member_key = 'trust'
    api_prefix = '/OS-TRUST'
    json_home_resource_rel_func = _build_resource_relation
    json_home_parameter_rel_func = _build_parameter_relation

    def _check_unrestricted(self):
        if self.oslo_context.is_admin:
            return
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
        ENFORCER.enforce_call(action='identity:get_trust',
                              build_target=_build_trust_target_enforcement)

        # NOTE(cmurphy) look up trust before doing is_admin authorization - to
        # maintain the API contract, we expect a missing trust to raise a 404
        # before we get to enforcement (lp#1840288)
        trust = PROVIDERS.trust_api.get_trust(trust_id)

        if self.oslo_context.is_admin:
            # policies are not loaded for the is_admin context, so need to
            # block access here
            raise exception.ForbiddenAction(
                action=_('Requested user has no relation to this trust'))

        # NOTE(cmurphy) As of Train, the default policies enforce the
        # identity:get_trust rule. However, in case the
        # identity:get_trust rule has been locally overridden by the
        # default that would have been produced by the sample config, we need
        # to enforce it again and warn that the behavior is changing.
        rules = policy._ENFORCER._enforcer.rules.get('identity:get_trust')
        # rule check_str is ""
        if isinstance(rules, op_checks.TrueCheck):
            LOG.warning(
                "The policy check string for rule \"identity:get_trust\" "
                "has been overridden to \"always true\". In the next release, "
                "this will cause the" "\"identity:get_trust\" action to "
                "be fully permissive as hardcoded enforcement will be "
                "removed. To correct this issue, either stop overriding the "
                "\"identity:get_trust\" rule in config to accept the "
                "defaults, or explicitly set a rule that is not empty."
            )
            _trustor_trustee_only(trust)

        _normalize_trust_expires_at(trust)
        _normalize_trust_roles(trust)
        return self.wrap_member(trust)

    def _list_trusts(self):
        trustor_user_id = flask.request.args.get('trustor_user_id')
        trustee_user_id = flask.request.args.get('trustee_user_id')
        if trustor_user_id:
            target = {'trust': {'trustor_user_id': trustor_user_id}}
            ENFORCER.enforce_call(action='identity:list_trusts_for_trustor',
                                  target_attr=target)
        elif trustee_user_id:
            target = {'trust': {'trustee_user_id': trustee_user_id}}
            ENFORCER.enforce_call(action='identity:list_trusts_for_trustee',
                                  target_attr=target)
        else:
            ENFORCER.enforce_call(action='identity:list_trusts')

        trusts = []

        # NOTE(cmurphy) As of Train, the default policies enforce the
        # identity:list_trusts rule and there are new policies in-code to
        # enforce identity:list_trusts_for_trustor and
        # identity:list_trusts_for_trustee. However, in case the
        # identity:list_trusts rule has been locally overridden by the default
        # that would have been produced by the sample config, we need to
        # enforce it again and warn that the behavior is changing.
        rules = policy._ENFORCER._enforcer.rules.get('identity:list_trusts')
        # rule check_str is ""
        if isinstance(rules, op_checks.TrueCheck):
            LOG.warning(
                "The policy check string for rule \"identity:list_trusts\" "
                "has been overridden to \"always true\". In the next release, "
                "this will cause the \"identity:list_trusts\" action to be "
                "fully permissive as hardcoded enforcement will be removed. "
                "To correct this issue, either stop overriding the "
                "\"identity:list_trusts\" rule in config to accept the "
                "defaults, or explicitly set a rule that is not empty."
            )
            if not flask.request.args:
                # NOTE(morgan): Admin can list all trusts.
                ENFORCER.enforce_call(action='admin_required')

        if not flask.request.args:
            trusts += PROVIDERS.trust_api.list_trusts()
        elif trustor_user_id:
            trusts += PROVIDERS.trust_api.list_trusts_for_trustor(
                trustor_user_id)
        elif trustee_user_id:
            trusts += PROVIDERS.trust_api.list_trusts_for_trustee(
                trustee_user_id)

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
        trust = self.request_body_json.get('trust', {})
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
        return self.wrap_member(return_trust), http.client.CREATED

    def delete(self, trust_id):
        ENFORCER.enforce_call(action='identity:delete_trust',
                              build_target=_build_trust_target_enforcement)
        self._check_unrestricted()

        # NOTE(cmurphy) As of Train, the default policies enforce the
        # identity:delete_trust rule. However, in case the
        # identity:delete_trust rule has been locally overridden by the
        # default that would have been produced by the sample config, we need
        # to enforce it again and warn that the behavior is changing.
        rules = policy._ENFORCER._enforcer.rules.get('identity:delete_trust')
        # rule check_str is ""
        if isinstance(rules, op_checks.TrueCheck):
            LOG.warning(
                "The policy check string for rule \"identity:delete_trust\" "
                "has been overridden to \"always true\". In the next release, "
                "this will cause the" "\"identity:delete_trust\" action to "
                "be fully permissive as hardcoded enforcement will be "
                "removed. To correct this issue, either stop overriding the "
                "\"identity:delete_trust\" rule in config to accept the "
                "defaults, or explicitly set a rule that is not empty."
            )
            trust = PROVIDERS.trust_api.get_trust(trust_id)
            if (self.oslo_context.user_id != trust.get('trustor_user_id') and
                    not self.oslo_context.is_admin):
                action = _('Only admin or trustor can delete a trust')
                raise exception.ForbiddenAction(action=action)
        PROVIDERS.trust_api.delete_trust(trust_id,
                                         initiator=self.audit_initiator)
        return '', http.client.NO_CONTENT


# NOTE(morgan): Since this Resource is not being used with the automatic
# URL additions and does not have a collection key/member_key, we use
# the flask-restful Resource, not the keystone ResourceBase
class RolesForTrustListResource(flask_restful.Resource):

    @property
    def oslo_context(self):
        return flask.request.environ.get(context.REQUEST_CONTEXT_ENV, None)

    def get(self, trust_id):
        ENFORCER.enforce_call(action='identity:list_roles_for_trust',
                              build_target=_build_trust_target_enforcement)

        # NOTE(morgan): This duplicates a little of the .get_trust from the
        # main resource, as it needs some of the same logic. However, due to
        # how flask-restful works, this should be fully encapsulated

        if self.oslo_context.is_admin:
            # policies are not loaded for the is_admin context, so need to
            # block access here
            raise exception.ForbiddenAction(
                action=_('Requested user has no relation to this trust'))

        trust = PROVIDERS.trust_api.get_trust(trust_id)

        # NOTE(cmurphy) As of Train, the default policies enforce the
        # identity:list_roles_for_trust rule. However, in case the
        # identity:list_roles_for_trust rule has been locally overridden by the
        # default that would have been produced by the sample config, we need
        # to enforce it again and warn that the behavior is changing.
        rules = policy._ENFORCER._enforcer.rules.get(
            'identity:list_roles_for_trust')
        # rule check_str is ""
        if isinstance(rules, op_checks.TrueCheck):
            LOG.warning(
                "The policy check string for rule "
                "\"identity:list_roles_for_trust\" has been overridden to "
                "\"always true\". In the next release, this will cause the "
                "\"identity:list_roles_for_trust\" action to be fully "
                "permissive as hardcoded enforcement will be removed. To "
                "correct this issue, either stop overriding the "
                "\"identity:get_trust\" rule in config to accept the "
                "defaults, or explicitly set a rule that is not empty."
            )
            _trustor_trustee_only(trust)

        _normalize_trust_expires_at(trust)
        _normalize_trust_roles(trust)
        return {'roles': trust['roles'],
                'links': trust['roles_links']}


# NOTE(morgan): Since this Resource is not being used with the automatic
# URL additions and does not have a collection key/member_key, we use
# the flask-restful Resource, not the keystone ResourceBase
class RoleForTrustResource(flask_restful.Resource):

    @property
    def oslo_context(self):
        return flask.request.environ.get(context.REQUEST_CONTEXT_ENV, None)

    def get(self, trust_id, role_id):
        """Get a role that has been assigned to a trust."""
        ENFORCER.enforce_call(action='identity:get_role_for_trust',
                              build_target=_build_trust_target_enforcement)

        if self.oslo_context.is_admin:
            # policies are not loaded for the is_admin context, so need to
            # block access here
            raise exception.ForbiddenAction(
                action=_('Requested user has no relation to this trust'))

        trust = PROVIDERS.trust_api.get_trust(trust_id)

        # NOTE(cmurphy) As of Train, the default policies enforce the
        # identity:get_role_for_trust rule. However, in case the
        # identity:get_role_for_trust rule has been locally overridden by the
        # default that would have been produced by the sample config, we need
        # to enforce it again and warn that the behavior is changing.
        rules = policy._ENFORCER._enforcer.rules.get(
            'identity:get_role_for_trust')
        # rule check_str is ""
        if isinstance(rules, op_checks.TrueCheck):
            LOG.warning(
                "The policy check string for rule "
                "\"identity:get_role_for_trust\" has been overridden to "
                "\"always true\". In the next release, this will cause the "
                "\"identity:get_role_for_trust\" action to be fully "
                "permissive as hardcoded enforcement will be removed. To "
                "correct this issue, either stop overriding the "
                "\"identity:get_role_for_trust\" rule in config to accept the "
                "defaults, or explicitly set a rule that is not empty."
            )
            _trustor_trustee_only(trust)

        if not any(role['id'] == role_id for role in trust['roles']):
            raise exception.RoleNotFound(role_id=role_id)

        role = PROVIDERS.role_api.get_role(role_id)
        return ks_flask.ResourceBase.wrap_member(role, collection_name='roles',
                                                 member_name='role')


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

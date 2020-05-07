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

"""Unified in-memory token model."""

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_serialization import msgpackutils
from oslo_utils import reflection

from keystone.common import cache
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _

LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs

# supported token versions
V3 = 'v3.0'
VERSIONS = frozenset([V3])

# minimum access rules support
ACCESS_RULES_MIN_VERSION = 1.0


class TokenModel(object):
    """An object that represents a token emitted by keystone.

    This is a queryable object that other parts of keystone can use to reason
    about a user's authentication or authorization.
    """

    def __init__(self):
        self.user_id = None
        self.__user = None
        self.__user_domain = None

        self.methods = None
        self.audit_id = None
        self.parent_audit_id = None

        self.__expires_at = None
        self.__issued_at = None

        self.system = None

        self.domain_id = None
        self.__domain = None

        self.project_id = None
        self.__project = None
        self.__project_domain = None

        self.trust_id = None
        self.__trust = None
        self.__trustor = None
        self.__trustee = None
        self.__trust_project = None
        self.__trust_project_domain = None

        self.is_federated = False
        self.identity_provider_id = None
        self.protocol_id = None
        self.federated_groups = None

        self.access_token_id = None
        self.__access_token = None

        self.application_credential_id = None
        self.__application_credential = None

    def __repr__(self):
        """Return string representation of TokenModel."""
        desc = ('<%(type)s (audit_id=%(audit_id)s, '
                'audit_chain_id=%(audit_ids)s) at %(loc)s>')
        self_cls_name = reflection.get_class_name(self, fully_qualified=False)
        return desc % {'type': self_cls_name,
                       'audit_id': self.audit_id,
                       'audit_ids': self.audit_ids,
                       'loc': hex(id(self))}

    @property
    def audit_ids(self):
        if self.parent_audit_id:
            return [self.audit_id, self.parent_audit_id]
        return [self.audit_id]

    @property
    def expires_at(self):
        return self.__expires_at

    @expires_at.setter
    def expires_at(self, value):
        if not isinstance(value, str):
            raise ValueError('expires_at must be a string.')
        self.__expires_at = value

    @property
    def issued_at(self):
        return self.__issued_at

    @issued_at.setter
    def issued_at(self, value):
        if not isinstance(value, str):
            raise ValueError('issued_at must be a string.')
        self.__issued_at = value

    @property
    def unscoped(self):
        return not any(
            [self.system_scoped, self.domain_scoped, self.project_scoped,
             self.trust_scoped]
        )

    @property
    def system_scoped(self):
        return self.system is not None

    @property
    def user(self):
        if not self.__user:
            if self.user_id:
                self.__user = PROVIDERS.identity_api.get_user(self.user_id)
        return self.__user

    @property
    def user_domain(self):
        if not self.__user_domain:
            if self.user:
                self.__user_domain = PROVIDERS.resource_api.get_domain(
                    self.user['domain_id']
                )
        return self.__user_domain

    @property
    def domain(self):
        if not self.__domain:
            if self.domain_id:
                self.__domain = PROVIDERS.resource_api.get_domain(
                    self.domain_id
                )
        return self.__domain

    @property
    def domain_scoped(self):
        return self.domain_id is not None

    @property
    def project(self):
        if not self.__project:
            if self.project_id:
                self.__project = PROVIDERS.resource_api.get_project(
                    self.project_id
                )
        return self.__project

    @property
    def project_scoped(self):
        return self.project_id is not None

    @property
    def project_domain(self):
        if not self.__project_domain:
            if self.project and self.project.get('domain_id'):
                self.__project_domain = PROVIDERS.resource_api.get_domain(
                    self.project['domain_id']
                )
        return self.__project_domain

    @property
    def application_credential(self):
        if not self.__application_credential:
            if self.application_credential_id:
                app_cred_api = PROVIDERS.application_credential_api
                self.__application_credential = (
                    app_cred_api.get_application_credential(
                        self.application_credential_id
                    )
                )
        return self.__application_credential

    @property
    def oauth_scoped(self):
        return self.access_token_id is not None

    @property
    def access_token(self):
        if not self.__access_token:
            if self.access_token_id:
                self.__access_token = PROVIDERS.oauth_api.get_access_token(
                    self.access_token_id
                )
        return self.__access_token

    @property
    def trust_scoped(self):
        return self.trust_id is not None

    @property
    def trust(self):
        if not self.__trust:
            if self.trust_id:
                self.__trust = PROVIDERS.trust_api.get_trust(self.trust_id)
        return self.__trust

    @property
    def trustor(self):
        if not self.__trustor:
            if self.trust:
                self.__trustor = PROVIDERS.identity_api.get_user(
                    self.trust['trustor_user_id']
                )
        return self.__trustor

    @property
    def trustee(self):
        if not self.__trustee:
            if self.trust:
                self.__trustee = PROVIDERS.identity_api.get_user(
                    self.trust['trustee_user_id']
                )
        return self.__trustee

    @property
    def trust_project(self):
        if not self.__trust_project:
            if self.trust:
                self.__trust_project = PROVIDERS.resource_api.get_project(
                    self.trust['project_id']
                )
        return self.__trust_project

    @property
    def trust_project_domain(self):
        if not self.__trust_project_domain:
            if self.trust:
                self.__trust_project_domain = (
                    PROVIDERS.resource_api.get_domain(
                        self.trust_project['domain_id']
                    )
                )
        return self.__trust_project_domain

    def _get_system_roles(self):
        roles = []
        groups = PROVIDERS.identity_api.list_groups_for_user(self.user_id)
        all_group_roles = []
        assignments = []
        for group in groups:
            group_roles = (
                PROVIDERS.assignment_api.list_system_grants_for_group(
                    group['id']
                )
            )
            for role in group_roles:
                all_group_roles.append(role)
                assignment = {'group_id': group['id'], 'role_id': role['id']}
                assignments.append(assignment)
        user_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            self.user_id
        )
        for role in user_roles:
            assignment = {'user_id': self.user_id, 'role_id': role['id']}
            assignments.append(assignment)

        # NOTE(lbragstad): The whole reason we need to build out a list of
        # "assignments" as opposed to just using the nice list of roles we
        # already have is because the add_implied_roles() method operates on a
        # list of assignment dictionaries (containing role_id,
        # user_id/group_id, project_id, et cetera). That method could probably
        # be fixed to be more clear by operating on actual roles instead of
        # just assignments.
        assignments = PROVIDERS.assignment_api.add_implied_roles(assignments)
        for assignment in assignments:
            role = PROVIDERS.role_api.get_role(assignment['role_id'])
            roles.append({'id': role['id'], 'name': role['name']})

        return roles

    def _get_trust_roles(self):
        roles = []
        # If redelegated_trust_id is set, then we must traverse the trust_chain
        # in order to determine who the original trustor is. We need to do this
        # because the user ID of the original trustor helps us determine scope
        # in the redelegated context.
        if self.trust.get('redelegated_trust_id'):
            trust_chain = PROVIDERS.trust_api.get_trust_pedigree(
                self.trust_id
            )
            original_trustor_id = trust_chain[-1]['trustor_user_id']
        else:
            original_trustor_id = self.trustor['id']

        trust_roles = [
            {'role_id': role['id']} for role in self.trust['roles']
        ]
        effective_trust_roles = (
            PROVIDERS.assignment_api.add_implied_roles(trust_roles)
        )
        effective_trust_role_ids = (
            set([r['role_id'] for r in effective_trust_roles])
        )

        current_effective_trustor_roles = (
            PROVIDERS.assignment_api.get_roles_for_trustor_and_project(
                original_trustor_id, self.trust.get('project_id')
            )
        )

        for trust_role_id in effective_trust_role_ids:
            if trust_role_id in current_effective_trustor_roles:
                role = PROVIDERS.role_api.get_role(trust_role_id)
                if role['domain_id'] is None:
                    roles.append(role)
            else:
                raise exception.Forbidden(
                    _('Trustee has no delegated roles.'))

        return roles

    def _get_oauth_roles(self):
        roles = []
        access_token_roles = self.access_token['role_ids']
        access_token_roles = [
            {'role_id': r} for r in jsonutils.loads(access_token_roles)]
        effective_access_token_roles = (
            PROVIDERS.assignment_api.add_implied_roles(access_token_roles)
        )
        user_roles = [r['id'] for r in self._get_project_roles()]
        for role in effective_access_token_roles:
            if role['role_id'] in user_roles:
                role = PROVIDERS.role_api.get_role(role['role_id'])
                roles.append({'id': role['id'], 'name': role['name']})
        return roles

    def _get_federated_roles(self):
        roles = []
        group_ids = [group['id'] for group in self.federated_groups]
        federated_roles = PROVIDERS.assignment_api.get_roles_for_groups(
            group_ids, self.project_id, self.domain_id
        )
        for group_id in group_ids:
            group_roles = (
                PROVIDERS.assignment_api.list_system_grants_for_group(
                    group_id
                )
            )
            for role in group_roles:
                federated_roles.append(role)
        user_roles = PROVIDERS.assignment_api.list_system_grants_for_user(
            self.user_id
        )
        for role in user_roles:
            federated_roles.append(role)
        if self.domain_id:
            domain_roles = (
                PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                    self.user_id, self.domain_id
                )
            )
            for role in domain_roles:
                federated_roles.append(role)
        if self.project_id:
            project_roles = (
                PROVIDERS.assignment_api.get_roles_for_user_and_project(
                    self.user_id, self.project_id
                )
            )
            for role in project_roles:
                federated_roles.append(role)
        # NOTE(lbragstad): Remove duplicate role references from a list of
        # roles. It is often suggested that this be done with:
        #
        # roles = [dict(t) for t in set([tuple(d.items()) for d in roles])]
        #
        # But that doesn't actually remove duplicates in all cases and
        # causes transient failures because dictionaries are unordered
        # objects. This means {'id': 1, 'foo': 'bar'} and {'foo': 'bar',
        # 'id': 1} won't actually resolve to a single entity in the above
        # logic since they are both considered unique. By using `in` we're
        # performing a containment check, which also does a deep comparison
        # of the objects, which is what we want.
        for role in federated_roles:
            if not isinstance(role, dict):
                role = PROVIDERS.role_api.get_role(role)
            if role not in roles:
                roles.append(role)

        return roles

    def _get_domain_roles(self):
        roles = []
        domain_roles = (
            PROVIDERS.assignment_api.get_roles_for_user_and_domain(
                self.user_id, self.domain_id
            )
        )
        for role_id in domain_roles:
            role = PROVIDERS.role_api.get_role(role_id)
            roles.append({'id': role['id'], 'name': role['name']})

        return roles

    def _get_project_roles(self):
        roles = []
        project_roles = (
            PROVIDERS.assignment_api.get_roles_for_user_and_project(
                self.user_id, self.project_id
            )
        )
        for role_id in project_roles:
            r = PROVIDERS.role_api.get_role(role_id)
            roles.append({'id': r['id'], 'name': r['name']})

        return roles

    def _get_application_credential_roles(self):
        roles = []
        app_cred_roles = self.application_credential['roles']
        assignment_list = PROVIDERS.assignment_api.list_role_assignments(
            user_id=self.user_id,
            project_id=self.project_id,
            domain_id=self.domain_id,
            effective=True)
        user_roles = list(set([x['role_id'] for x in assignment_list]))

        for role in app_cred_roles:
            if role['id'] in user_roles:
                roles.append({'id': role['id'], 'name': role['name']})

        return roles

    @property
    def roles(self):
        if self.system_scoped:
            roles = self._get_system_roles()
        elif self.trust_scoped:
            roles = self._get_trust_roles()
        elif self.oauth_scoped:
            roles = self._get_oauth_roles()
        elif self.is_federated and not self.unscoped:
            roles = self._get_federated_roles()
        elif self.domain_scoped:
            roles = self._get_domain_roles()
        elif self.application_credential_id and self.project_id:
            roles = self._get_application_credential_roles()
        elif self.project_scoped:
            roles = self._get_project_roles()
        else:
            roles = []
        return roles

    def _validate_token_resources(self):
        if self.project and not self.project.get('enabled'):
            msg = ('Unable to validate token because project %(id)s is '
                   'disabled') % {'id': self.project_id}
            tr_msg = _('Unable to validate token because project %(id)s is '
                       'disabled') % {'id': self.project_id}
            LOG.warning(msg)
            raise exception.ProjectNotFound(tr_msg)
        if self.project and not self.project_domain.get('enabled'):
            msg = ('Unable to validate token because domain %(id)s is '
                   'disabled') % {'id': self.project_domain['id']}
            tr_msg = _('Unable to validate token because domain %(id)s is '
                       'disabled') % {'id': self.project_domain['id']}
            LOG.warning(msg)
            raise exception.DomainNotFound(tr_msg)

    def _validate_token_user(self):
        if self.trust_scoped:
            if self.user_id != self.trustee['id']:
                raise exception.Forbidden(_('User is not a trustee.'))
            try:
                PROVIDERS.resource_api.assert_domain_enabled(
                    self.trustor['domain_id']
                )
            except AssertionError:
                raise exception.TokenNotFound(_('Trustor domain is disabled.'))
            try:
                PROVIDERS.resource_api.assert_domain_enabled(
                    self.trustee['domain_id']
                )
            except AssertionError:
                raise exception.TokenNotFound(_('Trustee domain is disabled.'))

            try:
                PROVIDERS.identity_api.assert_user_enabled(
                    self.trustor['id']
                )
            except AssertionError:
                raise exception.Forbidden(_('Trustor is disabled.'))

        if not self.user_domain.get('enabled'):
            msg = ('Unable to validate token because domain %(id)s is '
                   'disabled') % {'id': self.user_domain['id']}
            tr_msg = _('Unable to validate token because domain %(id)s is '
                       'disabled') % {'id': self.user_domain['id']}
            LOG.warning(msg)
            raise exception.DomainNotFound(tr_msg)

    def _validate_system_scope(self):
        if self.system_scoped and not self.roles:
            msg = ('User %(user_id)s has no access to the system'
                   ) % {'user_id': self.user_id}
            tr_msg = _('User %(user_id)s has no access to the system'
                       ) % {'user_id': self.user_id}
            LOG.debug(msg)
            raise exception.Unauthorized(tr_msg)

    def _validate_domain_scope(self):
        if self.domain_scoped and not self.roles:
            msg = (
                'User %(user_id)s has no access to domain %(domain_id)s'
            ) % {'user_id': self.user_id, 'domain_id': self.domain_id}
            tr_msg = _(
                'User %(user_id)s has no access to domain %(domain_id)s'
            ) % {'user_id': self.user_id, 'domain_id': self.domain_id}
            LOG.debug(msg)
            raise exception.Unauthorized(tr_msg)

    def _validate_project_scope(self):
        if self.project_scoped and not self.roles:
            msg = (
                'User %(user_id)s has no access to project %(project_id)s'
            ) % {'user_id': self.user_id, 'project_id': self.project_id}
            tr_msg = _(
                'User %(user_id)s has no access to project %(project_id)s'
            ) % {'user_id': self.user_id, 'project_id': self.project_id}
            LOG.debug(msg)
            raise exception.Unauthorized(tr_msg)

    def _validate_trust_scope(self):
        trust_roles = []
        if self.trust_id:
            refs = [{'role_id': role['id']} for role in self.trust['roles']]
            effective_trust_roles = PROVIDERS.assignment_api.add_implied_roles(
                refs
            )
            effective_trust_role_ids = (
                set([r['role_id'] for r in effective_trust_roles])
            )
            current_effective_trustor_roles = (
                PROVIDERS.assignment_api.get_roles_for_trustor_and_project(
                    self.trustor['id'], self.trust.get('project_id')
                )
            )
            # Go through each of the effective trust roles, making sure the
            # trustor still has them, if any have been removed, then we
            # will treat the trust as invalid
            for trust_role_id in effective_trust_role_ids:
                if trust_role_id in current_effective_trustor_roles:
                    role = PROVIDERS.role_api.get_role(trust_role_id)
                    if role['domain_id'] is None:
                        trust_roles.append(role)
                else:
                    raise exception.Forbidden(
                        _('Trustee has no delegated roles.'))

    def mint(self, token_id, issued_at):
        """Set the ``id`` and ``issued_at`` attributes of a token.

        The process of building a token requires setting attributes about the
        authentication and authorization context, like ``user_id`` and
        ``project_id`` for example. Once a Token object accurately represents
        this information it should be "minted". Tokens are minted when they get
        an ``id`` attribute and their creation time is recorded.

        """
        self._validate_token_resources()
        self._validate_token_user()
        self._validate_system_scope()
        self._validate_domain_scope()
        self._validate_project_scope()
        self._validate_trust_scope()

        self.id = token_id
        self.issued_at = issued_at


class _TokenModelHandler(object):
    identity = 126
    handles = (TokenModel,)

    def __init__(self, registry):
        self._registry = registry

    def serialize(self, obj):
        serialized = msgpackutils.dumps(obj.__dict__, registry=self._registry)
        return serialized

    def deserialize(self, data):
        token_data = msgpackutils.loads(data, registry=self._registry)
        try:
            token_model = TokenModel()
            for k, v in iter(token_data.items()):
                setattr(token_model, k, v)
        except Exception:
            LOG.debug(
                "Failed to deserialize TokenModel. Data is %s", token_data
            )
            raise exception.CacheDeserializationError(
                TokenModel.__name__, token_data
            )
        return token_model


cache.register_model_handler(_TokenModelHandler)

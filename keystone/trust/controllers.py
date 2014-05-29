# Copyright 2013 OpenStack Foundation
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

import uuid

import six

from keystone import assignment
from keystone.common import controller
from keystone.common import dependency
from keystone import config
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log
from keystone.openstack.common import timeutils


LOG = log.getLogger(__name__)
CONF = config.CONF


def _trustor_only(context, trust, user_id):
    if user_id != trust.get('trustor_user_id'):
        raise exception.Forbidden()


def _trustor_trustee_only(trust, user_id):
    if (user_id != trust.get('trustee_user_id') and
            user_id != trust.get('trustor_user_id')):
                raise exception.Forbidden()


def _admin_trustor_only(context, trust, user_id):
    if user_id != trust.get('trustor_user_id') and not context['is_admin']:
        raise exception.Forbidden()


@dependency.requires('assignment_api', 'identity_api', 'trust_api',
                     'token_api')
class TrustV3(controller.V3Controller):
    collection_name = "trusts"
    member_name = "trust"

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""

        # NOTE(stevemar): Overriding path to /OS-TRUST/trusts so that
        # V3Controller.base_url handles setting the self link correctly.
        path = '/OS-TRUST/' + cls.collection_name
        return super(TrustV3, cls).base_url(context, path=path)

    def _get_user_id(self, context):
        if 'token_id' in context:
            token_id = context['token_id']
            token = self.token_api.get_token(token_id)
            user_id = token['user']['id']
            return user_id
        return None

    def get_trust(self, context, trust_id):
        user_id = self._get_user_id(context)
        trust = self.trust_api.get_trust(trust_id)
        if not trust:
            raise exception.TrustNotFound(trust_id)
        _trustor_trustee_only(trust, user_id)
        self._fill_in_roles(context, trust,
                            self.assignment_api.list_roles())
        return TrustV3.wrap_member(context, trust)

    def _fill_in_roles(self, context, trust, all_roles):
        if trust.get('expires_at') is not None:
            trust['expires_at'] = (timeutils.isotime
                                   (trust['expires_at'],
                                    subsecond=True))

        if 'roles' not in trust:
            trust['roles'] = []
        trust_full_roles = []
        for trust_role in trust['roles']:
            if isinstance(trust_role, six.string_types):
                trust_role = {'id': trust_role}
            matching_roles = [x for x in all_roles
                              if x['id'] == trust_role['id']]
            if matching_roles:
                full_role = assignment.controllers.RoleV3.wrap_member(
                    context, matching_roles[0])['role']
                trust_full_roles.append(full_role)
        trust['roles'] = trust_full_roles
        trust['roles_links'] = {
            'self': (self.base_url(context) + "/%s/roles" % trust['id']),
            'next': None,
            'previous': None}

    def _clean_role_list(self, context, trust, all_roles):
        trust_roles = []
        all_role_names = dict((r['name'], r) for r in all_roles)
        for role in trust.get('roles', []):
            if 'id' in role:
                trust_roles.append({'id': role['id']})
            elif 'name' in role:
                rolename = role['name']
                if rolename in all_role_names:
                    trust_roles.append({'id':
                                        all_role_names[rolename]['id']})
                else:
                    raise exception.RoleNotFound("role %s is not defined" %
                                                 rolename)
            else:
                raise exception.ValidationError(attribute='id or name',
                                                target='roles')
        return trust_roles

    @controller.protected()
    def create_trust(self, context, trust=None):
        """Create a new trust.

        The user creating the trust must be the trustor.

        """

        # TODO(ayoung): instead of raising ValidationError on the first
        # problem, return a collection of all the problems.

        # Explicitly prevent a trust token from creating a new trust.
        auth_context = context.get('environment',
                                   {}).get('KEYSTONE_AUTH_CONTEXT', {})
        if auth_context.get('is_delegated_auth'):
            raise exception.Forbidden(
                _('Cannot create a trust'
                  ' with a token issued via delegation.'))

        if not trust:
            raise exception.ValidationError(attribute='trust',
                                            target='request')
        if trust.get('project_id') and not trust.get('roles'):
            raise exception.Forbidden(
                _('At least one role should be specified.'))
        try:
            user_id = self._get_user_id(context)
            _trustor_only(context, trust, user_id)
            #confirm that the trustee exists
            self.identity_api.get_user(trust['trustee_user_id'])
            all_roles = self.assignment_api.list_roles()
            clean_roles = self._clean_role_list(context, trust, all_roles)
            if trust.get('project_id'):
                user_role = self.assignment_api.get_roles_for_user_and_project(
                    user_id,
                    trust['project_id'])
            else:
                user_role = []
            for trust_role in clean_roles:
                matching_roles = [x for x in user_role
                                  if x == trust_role['id']]
                if not matching_roles:
                    raise exception.RoleNotFound(role_id=trust_role['id'])
            if trust.get('expires_at') is not None:
                if not trust['expires_at'].endswith('Z'):
                    trust['expires_at'] += 'Z'
                try:
                    trust['expires_at'] = (timeutils.parse_isotime
                                           (trust['expires_at']))
                except ValueError:
                    raise exception.ValidationTimeStampError()
            trust_id = uuid.uuid4().hex
            new_trust = self.trust_api.create_trust(trust_id,
                                                    trust,
                                                    clean_roles)
            self._fill_in_roles(context, new_trust, all_roles)
            return TrustV3.wrap_member(context, new_trust)
        except KeyError as e:
            raise exception.ValidationError(attribute=e.args[0],
                                            target='trust')

    @controller.protected()
    def list_trusts(self, context):
        query = context['query_string']
        trusts = []
        if not query:
            self.assert_admin(context)
            trusts += self.trust_api.list_trusts()
        if 'trustor_user_id' in query:
            user_id = query['trustor_user_id']
            calling_user_id = self._get_user_id(context)
            if user_id != calling_user_id:
                raise exception.Forbidden()
            trusts += (self.trust_api.
                       list_trusts_for_trustor(user_id))
        if 'trustee_user_id' in query:
            user_id = query['trustee_user_id']
            calling_user_id = self._get_user_id(context)
            if user_id != calling_user_id:
                raise exception.Forbidden()
            trusts += self.trust_api.list_trusts_for_trustee(user_id)
        for trust in trusts:
            # get_trust returns roles, list_trusts does not
            # It seems in some circumstances, roles does not
            # exist in the query response, so check first
            if 'roles' in trust:
                del trust['roles']
            if trust.get('expires_at') is not None:
                trust['expires_at'] = (timeutils.isotime
                                       (trust['expires_at'],
                                        subsecond=True))
        return TrustV3.wrap_collection(context, trusts)

    @controller.protected()
    def delete_trust(self, context, trust_id):
        trust = self.trust_api.get_trust(trust_id)
        if not trust:
            raise exception.TrustNotFound(trust_id)

        user_id = self._get_user_id(context)
        _admin_trustor_only(context, trust, user_id)
        self.trust_api.delete_trust(trust_id)
        userid = trust['trustor_user_id']
        self.token_api.delete_tokens(userid, trust_id=trust_id)

    @controller.protected()
    def list_roles_for_trust(self, context, trust_id):
        trust = self.get_trust(context, trust_id)['trust']
        if not trust:
            raise exception.TrustNotFound(trust_id)
        user_id = self._get_user_id(context)
        _trustor_trustee_only(trust, user_id)
        return {'roles': trust['roles'],
                'links': trust['roles_links']}

    @controller.protected()
    def check_role_for_trust(self, context, trust_id, role_id):
        """Checks if a role has been assigned to a trust."""
        trust = self.trust_api.get_trust(trust_id)
        if not trust:
            raise exception.TrustNotFound(trust_id)
        user_id = self._get_user_id(context)
        _trustor_trustee_only(trust, user_id)
        if not any(role['id'] == role_id for role in trust['roles']):
            raise exception.RoleNotFound(role_id=role_id)

    @controller.protected()
    def get_role_for_trust(self, context, trust_id, role_id):
        """Get a role that has been assigned to a trust."""
        self.check_role_for_trust(context, trust_id, role_id)
        role = self.assignment_api.get_role(role_id)
        return assignment.controllers.RoleV3.wrap_member(context, role)

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

import copy
import datetime
import sqlalchemy

from oslo_config import cfg
from oslo_db import api as oslo_db_api

from keystone.common import provider_api
from keystone.common import sql
from keystone import exception
from keystone.identity.backends import base as identity_base
from keystone.identity.backends import sql_model as model
from keystone.identity.shadow_backends import base


CONF = cfg.CONF
PROVIDERS = provider_api.ProviderAPIs


class ShadowUsers(base.ShadowUsersDriverBase):
    @sql.handle_conflicts(conflict_type='federated_user')
    def create_federated_user(self, domain_id, federated_dict, email=None):

        local_entity = {'domain_id': domain_id,
                        'local_id': federated_dict['unique_id'],
                        'entity_type': 'user'}

        public_id = PROVIDERS.id_generator_api.generate_public_ID(local_entity)

        user = {
            'id': public_id,
            'domain_id': domain_id,
            'enabled': True
        }
        if email:
            user['email'] = email
        with sql.session_for_write() as session:
            federated_ref = model.FederatedUser.from_dict(federated_dict)
            user_ref = model.User.from_dict(user)
            user_ref.created_at = datetime.datetime.utcnow()
            user_ref.federated_users.append(federated_ref)
            session.add(user_ref)
            return identity_base.filter_user(user_ref.to_dict())

    @sql.handle_conflicts(conflict_type='federated_user')
    def create_federated_object(self, fed_dict):
        with sql.session_for_write() as session:
            fed_ref = model.FederatedUser.from_dict(fed_dict)
            session.add(fed_ref)

    def delete_federated_object(self, user_id):
        with sql.session_for_write() as session:
            q = session.query(model.FederatedUser)
            q = q.filter(model.FederatedUser.user_id == user_id)
            q.delete(False)

    def get_federated_objects(self, user_id):
        with sql.session_for_read() as session:
            query = session.query(model.FederatedUser)
            query = query.filter(model.FederatedUser.user_id == user_id)
            fed_ref = []
            for row in query:
                m = model.FederatedUser(
                    idp_id=row.idp_id,
                    protocol_id=row.protocol_id,
                    unique_id=row.unique_id)
                fed_ref.append(m.to_dict())
            return base.federated_objects_to_list(fed_ref)

    def _update_query_with_federated_statements(self, hints, query):
        statements = []
        for filter_ in hints.filters:
            if filter_['name'] == 'idp_id':
                statements.append(
                    model.FederatedUser.idp_id == filter_['value'])
            if filter_['name'] == 'protocol_id':
                statements.append(
                    model.FederatedUser.protocol_id == filter_['value'])
            if filter_['name'] == 'unique_id':
                statements.append(
                    model.FederatedUser.unique_id == filter_['value'])

        # Remove federated attributes to prevent redundancies from
        # sql.filter_limit_query which filters remaining hints
        hints.filters = [
            x for x in hints.filters if x['name'] not in ('idp_id',
                                                          'protocol_id',
                                                          'unique_id')]
        if statements:
            query = query.filter(sqlalchemy.and_(*statements))
        return query

    def get_federated_users(self, hints):
        with sql.session_for_read() as session:
            query = session.query(model.User).outerjoin(
                model.LocalUser).outerjoin(model.FederatedUser)
            query = query.filter(model.User.id == model.FederatedUser.user_id)
            query = self._update_query_with_federated_statements(hints, query)
            name_filter = None
            for filter_ in hints.filters:
                if filter_['name'] == 'name':
                    name_filter = filter_
                    query = query.filter(
                        model.FederatedUser.display_name == name_filter[
                            'value'])
                    break
            if name_filter:
                hints.filters.remove(name_filter)
            user_refs = sql.filter_limit_query(model.User, query, hints)
            return [identity_base.filter_user(x.to_dict()) for x in user_refs]

    def get_federated_user(self, idp_id, protocol_id, unique_id):
        # NOTE(notmorgan): Open a session here to ensure .to_dict is called
        # within an active session context. This will prevent lazy-load
        # relationship failure edge-cases
        # FIXME(notmorgan): Eventually this should not call `to_dict` here and
        # rely on something already in the session context to perform the
        # `to_dict` call.
        with sql.session_for_read():
            user_ref = self._get_federated_user(idp_id, protocol_id, unique_id)
            return identity_base.filter_user(user_ref.to_dict())

    def _get_federated_user(self, idp_id, protocol_id, unique_id):
        """Return the found user for the federated identity.

        :param idp_id: The identity provider ID
        :param protocol_id: The federation protocol ID
        :param unique_id: The user's unique ID (unique within the IdP)
        :returns User: Returns a reference to the User

        """
        with sql.session_for_read() as session:
            query = session.query(model.User).outerjoin(model.LocalUser)
            query = query.join(model.FederatedUser)
            query = query.filter(model.FederatedUser.idp_id == idp_id)
            query = query.filter(model.FederatedUser.protocol_id ==
                                 protocol_id)
            query = query.filter(model.FederatedUser.unique_id == unique_id)
            try:
                user_ref = query.one()
            except sql.NotFound:
                raise exception.UserNotFound(user_id=unique_id)
            return user_ref

    def set_last_active_at(self, user_id):
        if CONF.security_compliance.disable_user_account_days_inactive:
            with sql.session_for_write() as session:
                user_ref = session.query(model.User).get(user_id)
                user_ref.last_active_at = datetime.datetime.utcnow().date()

    @sql.handle_conflicts(conflict_type='federated_user')
    def update_federated_user_display_name(self, idp_id, protocol_id,
                                           unique_id, display_name):
        with sql.session_for_write() as session:
            query = session.query(model.FederatedUser)
            query = query.filter(model.FederatedUser.idp_id == idp_id)
            query = query.filter(model.FederatedUser.protocol_id ==
                                 protocol_id)
            query = query.filter(model.FederatedUser.unique_id == unique_id)
            query = query.filter(model.FederatedUser.display_name !=
                                 display_name)
            query.update({'display_name': display_name})
            return

    @sql.handle_conflicts(conflict_type='nonlocal_user')
    def create_nonlocal_user(self, user_dict):
        new_user_dict = copy.deepcopy(user_dict)
        # remove local_user attributes from new_user_dict
        new_user_dict.pop('name', None)
        new_user_dict.pop('password', None)
        # create nonlocal_user dict
        new_nonlocal_user_dict = {
            'name': user_dict['name']
        }
        with sql.session_for_write() as session:
            new_nonlocal_user_ref = model.NonLocalUser.from_dict(
                new_nonlocal_user_dict)
            new_user_ref = model.User.from_dict(new_user_dict)
            new_user_ref.created_at = datetime.datetime.utcnow()
            new_user_ref.nonlocal_user = new_nonlocal_user_ref
            session.add(new_user_ref)
            return identity_base.filter_user(new_user_ref.to_dict())

    @oslo_db_api.wrap_db_retry(retry_on_deadlock=True)
    def delete_user(self, user_id):
        with sql.session_for_write() as session:
            ref = self._get_user(session, user_id)

            q = session.query(model.UserGroupMembership)
            q = q.filter_by(user_id=user_id)
            q.delete(False)

            session.delete(ref)

    def get_user(self, user_id):
        with sql.session_for_read() as session:
            user_ref = self._get_user(session, user_id)
            return identity_base.filter_user(user_ref.to_dict())

    def _get_user(self, session, user_id):
        user_ref = session.query(model.User).get(user_id)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_id)
        return user_ref

    def list_federated_users_info(self, hints=None):
        with sql.session_for_read() as session:
            query = session.query(model.FederatedUser)
            fed_user_refs = sql.filter_limit_query(model.FederatedUser, query,
                                                   hints)
            return [x.to_dict() for x in fed_user_refs]

    def add_user_to_group_expires(self, user_id, group_id):
        def get_federated_user():
            with sql.session_for_read() as session:
                query = session.query(model.FederatedUser)
                query = query.filter_by(user_id=user_id)
                user = query.first()
                if not user:
                    # Note(knikolla): This shouldn't really ever happen, since
                    # this requires the user to already be logged in.
                    raise exception.UserNotFound(user_id=user_id)
                return user

        with sql.session_for_write() as session:
            user = get_federated_user()
            query = session.query(model.ExpiringUserGroupMembership)
            query = query.filter_by(user_id=user_id)
            query = query.filter_by(group_id=group_id)
            membership = query.first()

            if membership:
                membership.last_verified = datetime.datetime.utcnow()
            else:
                session.add(model.ExpiringUserGroupMembership(
                    user_id=user_id,
                    group_id=group_id,
                    idp_id=user.idp_id,
                    last_verified=datetime.datetime.utcnow()
                ))

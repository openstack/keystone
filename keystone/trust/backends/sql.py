# Copyright 2012 OpenStack Foundation
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

from oslo_utils import timeutils

import sqlalchemy
from sqlalchemy.ext.hybrid import hybrid_property

from keystone.common import sql
from keystone import exception
from keystone.trust.backends import base


# The maximum number of iterations that will be attempted for optimistic
# locking on consuming a limited-use trust.
MAXIMUM_CONSUME_ATTEMPTS = 10


class TrustModel(sql.ModelBase, sql.ModelDictMixinWithExtras):
    __tablename__ = 'trust'
    attributes = ['id', 'trustor_user_id', 'trustee_user_id',
                  'project_id', 'impersonation', 'expires_at',
                  'remaining_uses', 'deleted_at', 'redelegated_trust_id',
                  'redelegation_count']
    id = sql.Column(sql.String(64), primary_key=True)
    # user id of owner
    trustor_user_id = sql.Column(sql.String(64), nullable=False,)
    # user_id of user allowed to consume this preauth
    trustee_user_id = sql.Column(sql.String(64), nullable=False)
    project_id = sql.Column(sql.String(64))
    impersonation = sql.Column(sql.Boolean, nullable=False)
    deleted_at = sql.Column(sql.DateTime)
    _expires_at = sql.Column('expires_at', sql.DateTime)
    expires_at_int = sql.Column(sql.DateTimeInt(), nullable=True)
    remaining_uses = sql.Column(sql.Integer, nullable=True)
    redelegated_trust_id = sql.Column(sql.String(64), nullable=True)
    redelegation_count = sql.Column(sql.Integer, nullable=True)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint(
                      'trustor_user_id', 'trustee_user_id', 'project_id',
                      'impersonation', 'expires_at',
                      name='duplicate_trust_constraint'),)

    @hybrid_property
    def expires_at(self):
        return self.expires_at_int or self._expires_at

    @expires_at.setter
    def expires_at(self, value):
        self._expires_at = value
        self.expires_at_int = value


class TrustRole(sql.ModelBase):
    __tablename__ = 'trust_role'
    attributes = ['trust_id', 'role_id']
    trust_id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    role_id = sql.Column(sql.String(64), primary_key=True, nullable=False)


class Trust(base.TrustDriverBase):
    @sql.handle_conflicts(conflict_type='trust')
    def create_trust(self, trust_id, trust, roles):
        with sql.session_for_write() as session:
            ref = TrustModel.from_dict(trust)
            ref['id'] = trust_id
            if ref.get('expires_at') and ref['expires_at'].tzinfo is not None:
                ref['expires_at'] = timeutils.normalize_time(ref['expires_at'])
            session.add(ref)
            added_roles = []
            for role in roles:
                trust_role = TrustRole()
                trust_role.trust_id = trust_id
                trust_role.role_id = role['id']
                added_roles.append({'id': role['id']})
                session.add(trust_role)
            trust_dict = ref.to_dict()
            trust_dict['roles'] = added_roles
            return trust_dict

    def _add_roles(self, trust_id, session, trust_dict):
        roles = []
        for role in session.query(TrustRole).filter_by(trust_id=trust_id):
            roles.append({'id': role.role_id})
        trust_dict['roles'] = roles

    def consume_use(self, trust_id):
        for attempt in range(MAXIMUM_CONSUME_ATTEMPTS):
            with sql.session_for_write() as session:
                try:
                    query_result = (session.query(TrustModel.remaining_uses).
                                    filter_by(id=trust_id).
                                    filter_by(deleted_at=None).one())
                except sql.NotFound:
                    raise exception.TrustNotFound(trust_id=trust_id)

                remaining_uses = query_result.remaining_uses

                if remaining_uses is None:
                    # unlimited uses, do nothing
                    break
                elif remaining_uses > 0:
                    # NOTE(morganfainberg): use an optimistic locking method
                    # to ensure we only ever update a trust that has the
                    # expected number of remaining uses.
                    rows_affected = (
                        session.query(TrustModel).
                        filter_by(id=trust_id).
                        filter_by(deleted_at=None).
                        filter_by(remaining_uses=remaining_uses).
                        update({'remaining_uses': (remaining_uses - 1)},
                               synchronize_session=False))
                    if rows_affected == 1:
                        # Successfully consumed a single limited-use trust.
                        # Since trust_id is the PK on the Trust table, there is
                        # no case we should match more than 1 row in the
                        # update. We either update 1 row or 0 rows.
                        break
                else:
                    raise exception.TrustUseLimitReached(trust_id=trust_id)
        else:
            # NOTE(morganfainberg): In the case the for loop is not prematurely
            # broken out of, this else block is executed. This means the trust
            # was not unlimited nor was it consumed (we hit the maximum
            # iteration limit). This is just an indicator that we were unable
            # to get the optimistic lock rather than silently failing or
            # incorrectly indicating a trust was consumed.
            raise exception.TrustConsumeMaximumAttempt(trust_id=trust_id)

    def get_trust(self, trust_id, deleted=False):
        with sql.session_for_read() as session:
            query = session.query(TrustModel).filter_by(id=trust_id)
            if not deleted:
                query = query.filter_by(deleted_at=None)
            ref = query.first()
            if ref is None:
                raise exception.TrustNotFound(trust_id=trust_id)
            if ref.expires_at is not None and not deleted:
                now = timeutils.utcnow()
                if now > ref.expires_at:
                    raise exception.TrustNotFound(trust_id=trust_id)
            # Do not return trusts that can't be used anymore
            if ref.remaining_uses is not None and not deleted:
                if ref.remaining_uses <= 0:
                    raise exception.TrustNotFound(trust_id=trust_id)
            trust_dict = ref.to_dict()

            self._add_roles(trust_id, session, trust_dict)
            return trust_dict

    def list_trusts(self):
        with sql.session_for_read() as session:
            trusts = session.query(TrustModel).filter_by(deleted_at=None)
            return [trust_ref.to_dict() for trust_ref in trusts]

    def list_trusts_for_trustee(self, trustee_user_id):
        with sql.session_for_read() as session:
            trusts = (session.query(TrustModel).
                      filter_by(deleted_at=None).
                      filter_by(trustee_user_id=trustee_user_id))
            return [trust_ref.to_dict() for trust_ref in trusts]

    def list_trusts_for_trustor(self, trustor_user_id,
                                redelegated_trust_id=None):
        with sql.session_for_read() as session:
            trusts = (session.query(TrustModel).
                      filter_by(deleted_at=None).
                      filter_by(trustor_user_id=trustor_user_id))
            if redelegated_trust_id:
                trusts = trusts.filter_by(
                    redelegated_trust_id=redelegated_trust_id)
            return [trust_ref.to_dict() for trust_ref in trusts]

    @sql.handle_conflicts(conflict_type='trust')
    def delete_trust(self, trust_id):
        with sql.session_for_write() as session:
            trust_ref = session.query(TrustModel).get(trust_id)
            if not trust_ref:
                raise exception.TrustNotFound(trust_id=trust_id)
            trust_ref.deleted_at = timeutils.utcnow()

    def delete_trusts_for_project(self, project_id):
        with sql.session_for_write() as session:
            query = session.query(TrustModel)
            trusts = query.filter_by(project_id=project_id)
            for trust_ref in trusts:
                trust_ref.deleted_at = timeutils.utcnow()

    def flush_expired_and_soft_deleted_trusts(self, project_id=None,
                                              trustor_user_id=None,
                                              trustee_user_id=None,
                                              date=None):
        with sql.session_for_write() as session:
            query = session.query(TrustModel)
            query = query.\
                filter(sqlalchemy.or_(TrustModel.deleted_at.isnot(None),
                                      sqlalchemy.and_(
                                          TrustModel.expires_at.isnot(None),
                                          TrustModel.expires_at < date)))
            if project_id:
                query = query.filter_by(project_id=project_id)
            if trustor_user_id:
                query = query.filter_by(trustor_user_id=trustor_user_id)
            if trustee_user_id:
                query = query.filter_by(trustee_user_id=trustee_user_id)
            query.delete(synchronize_session=False)
            session.flush()

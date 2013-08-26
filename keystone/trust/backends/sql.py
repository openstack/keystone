# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.common import sql
from keystone import exception
from keystone.openstack.common import timeutils
from keystone import trust


class TrustModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'trust'
    attributes = ['id', 'trustor_user_id', 'trustee_user_id',
                  'project_id', 'impersonation', 'expires_at']
    id = sql.Column(sql.String(64), primary_key=True)
    #user id Of owner
    trustor_user_id = sql.Column(sql.String(64), nullable=False,)
    #user_id of user allowed to consume this preauth
    trustee_user_id = sql.Column(sql.String(64), nullable=False)
    project_id = sql.Column(sql.String(64))
    impersonation = sql.Column(sql.Boolean, nullable=False)
    deleted_at = sql.Column(sql.DateTime)
    expires_at = sql.Column(sql.DateTime)
    extra = sql.Column(sql.JsonBlob())


class TrustRole(sql.ModelBase):
    __tablename__ = 'trust_role'
    attributes = ['trust_id', 'role_id']
    trust_id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    role_id = sql.Column(sql.String(64), primary_key=True, nullable=False)


class Trust(sql.Base, trust.Driver):
    @sql.handle_conflicts(type='trust')
    def create_trust(self, trust_id, trust, roles):
        session = self.get_session()
        with session.begin():
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
            session.flush()
        trust_dict = ref.to_dict()
        trust_dict['roles'] = added_roles
        return trust_dict

    def _add_roles(self, trust_id, session, trust_dict):
        roles = []
        for role in session.query(TrustRole).filter_by(trust_id=trust_id):
            roles.append({'id': role.role_id})
        trust_dict['roles'] = roles

    @sql.handle_conflicts(type='trust')
    def get_trust(self, trust_id):
        session = self.get_session()
        ref = (session.query(TrustModel).
               filter_by(deleted_at=None).
               filter_by(id=trust_id).first())
        if ref is None:
            return None
        if ref.expires_at is not None:
            now = timeutils.utcnow()
            if now > ref.expires_at:
                return None
        trust_dict = ref.to_dict()

        self._add_roles(trust_id, session, trust_dict)
        return trust_dict

    @sql.handle_conflicts(type='trust')
    def list_trusts(self):
        session = self.get_session()
        trusts = session.query(TrustModel).filter_by(deleted_at=None)
        return [trust_ref.to_dict() for trust_ref in trusts]

    @sql.handle_conflicts(type='trust')
    def list_trusts_for_trustee(self, trustee_user_id):
        session = self.get_session()
        trusts = (session.query(TrustModel).
                  filter_by(deleted_at=None).
                  filter_by(trustee_user_id=trustee_user_id))
        return [trust_ref.to_dict() for trust_ref in trusts]

    @sql.handle_conflicts(type='trust')
    def list_trusts_for_trustor(self, trustor_user_id):
        session = self.get_session()
        trusts = (session.query(TrustModel).
                  filter_by(deleted_at=None).
                  filter_by(trustor_user_id=trustor_user_id))
        return [trust_ref.to_dict() for trust_ref in trusts]

    @sql.handle_conflicts(type='trust')
    def delete_trust(self, trust_id):
        session = self.get_session()
        with session.begin():
            trust_ref = session.query(TrustModel).get(trust_id)
            if not trust_ref:
                raise exception.TrustNotFound(trust_id=trust_id)
            trust_ref.deleted_at = timeutils.utcnow()
            session.flush()

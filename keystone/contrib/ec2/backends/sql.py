# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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


class Ec2Credential(sql.ModelBase, sql.DictBase):
    __tablename__ = 'ec2_credential'
    access = sql.Column(sql.String(64), primary_key=True)
    secret = sql.Column(sql.String(64))
    user_id = sql.Column(sql.String(64))
    tenant_id = sql.Column(sql.String(64))

    @classmethod
    def from_dict(cls, user_dict):
        return cls(**user_dict)

    def to_dict(self):
        return dict(self.iteritems())


class Ec2(sql.Base):
    def get_credential(self, credential_id):
        session = self.get_session()
        credential_ref = session.query(Ec2Credential)\
                                .filter_by(access=credential_id).first()
        if not credential_ref:
            return
        return credential_ref.to_dict()

    def list_credentials(self, user_id):
        session = self.get_session()
        credential_refs = session.query(Ec2Credential)\
                                 .filter_by(user_id=user_id)
        return [x.to_dict() for x in credential_refs]

    # CRUD
    def create_credential(self, credential_id, credential):
        session = self.get_session()
        with session.begin():
            credential_ref = Ec2Credential.from_dict(credential)
            session.add(credential_ref)
            session.flush()
        return credential_ref.to_dict()

    def delete_credential(self, credential_id):
        session = self.get_session()
        credential_ref = session.query(Ec2Credential)\
                                .filter_by(access=credential_id).first()
        with session.begin():
            session.delete(credential_ref)
            session.flush()

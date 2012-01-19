# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone.common import sql
from keystone.common.sql import migration


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

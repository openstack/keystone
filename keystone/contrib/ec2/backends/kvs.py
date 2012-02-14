# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone.common import kvs


class Ec2(kvs.Base):
    # Public interface
    def get_credential(self, credential_id):
        credential_ref = self.db.get('credential-%s' % credential_id)
        return credential_ref

    def list_credentials(self, user_id):
        credential_ids = self.db.get('credential_list', [])
        rv = [self.get_credential(x) for x in credential_ids]
        return [x for x in rv if x['user_id'] == user_id]

    # CRUD
    def create_credential(self, credential_id, credential):
        self.db.set('credential-%s' % credential_id, credential)
        credential_list = set(self.db.get('credential_list', []))
        credential_list.add(credential_id)
        self.db.set('credential_list', list(credential_list))
        return credential

    def delete_credential(self, credential_id):
        old_credential = self.db.get('credential-%s' % credential_id)
        self.db.delete('credential-%s' % credential_id)
        credential_list = set(self.db.get('credential_list', []))
        credential_list.remove(credential_id)
        self.db.set('credential_list', list(credential_list))
        return None

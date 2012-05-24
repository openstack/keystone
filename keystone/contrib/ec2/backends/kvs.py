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
        # This will ensure credential-%s is here before deleting
        self.db.get('credential-%s' % credential_id)
        self.db.delete('credential-%s' % credential_id)
        credential_list = set(self.db.get('credential_list', []))
        credential_list.remove(credential_id)
        self.db.set('credential_list', list(credential_list))
        return None

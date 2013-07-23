# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
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

import hashlib
import json

from keystone.common import controller
from keystone import exception


class CredentialV3(controller.V3Controller):
    collection_name = 'credentials'
    member_name = 'credential'

    def __init__(self):
        super(CredentialV3, self).__init__()
        self.get_member_from_driver = self.credential_api.get_credential

    def _assign_unique_id(self, ref):
        # Generates and assigns a unique identifer to
        # a credential reference.
        if ref.get('type', '').lower() == 'ec2':
            try:
                blob = json.loads(ref.get('blob'))
            except (ValueError, TypeError):
                raise exception.ValidationError(
                    message=_('Invalid blob in credential'))
            if not blob or not isinstance(blob, dict):
                raise exception.ValidationError(attribute='blob',
                                                target='credential')
            if blob.get('access') is None:
                raise exception.ValidationError(attribute='access',
                                                target='blob')
            ref = ref.copy()
            ref['id'] = hashlib.sha256(blob['access']).hexdigest()
            return ref
        else:
            return super(CredentialV3, self)._assign_unique_id(ref)

    @controller.protected()
    def create_credential(self, context, credential):
        ref = self._assign_unique_id(self._normalize_dict(credential))
        ref = self.credential_api.create_credential(ref['id'], ref)
        return CredentialV3.wrap_member(context, ref)

    @controller.protected()
    def list_credentials(self, context):
        refs = self.credential_api.list_credentials()
        return CredentialV3.wrap_collection(context, refs)

    @controller.protected()
    def get_credential(self, context, credential_id):
        ref = self.credential_api.get_credential(credential_id)
        return CredentialV3.wrap_member(context, ref)

    @controller.protected()
    def update_credential(self, context, credential_id, credential):
        self._require_matching_id(credential_id, credential)

        ref = self.credential_api.update_credential(credential_id, credential)
        return CredentialV3.wrap_member(context, ref)

    @controller.protected()
    def delete_credential(self, context, credential_id):
        return self.credential_api.delete_credential(credential_id)

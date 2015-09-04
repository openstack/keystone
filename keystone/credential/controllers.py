# Copyright 2013 OpenStack Foundation
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

from oslo_serialization import jsonutils

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone.credential import schema
from keystone import exception
from keystone.i18n import _


@dependency.requires('credential_api')
class CredentialV3(controller.V3Controller):
    collection_name = 'credentials'
    member_name = 'credential'

    def __init__(self):
        super(CredentialV3, self).__init__()
        self.get_member_from_driver = self.credential_api.get_credential

    def _assign_unique_id(self, ref, trust_id=None):
        # Generates and assigns a unique identifier to
        # a credential reference.
        if ref.get('type', '').lower() == 'ec2':
            try:
                blob = jsonutils.loads(ref.get('blob'))
            except (ValueError, TypeError):
                raise exception.ValidationError(
                    message=_('Invalid blob in credential'))
            if not blob or not isinstance(blob, dict):
                raise exception.ValidationError(attribute='blob',
                                                target='credential')
            if blob.get('access') is None:
                raise exception.ValidationError(attribute='access',
                                                target='blob')
            ret_ref = ref.copy()
            ret_ref['id'] = hashlib.sha256(blob['access']).hexdigest()
            # Update the blob with the trust_id, so credentials created
            # with a trust scoped token will result in trust scoped
            # tokens when authentication via ec2tokens happens
            if trust_id is not None:
                blob['trust_id'] = trust_id
                ret_ref['blob'] = jsonutils.dumps(blob)
            return ret_ref
        else:
            return super(CredentialV3, self)._assign_unique_id(ref)

    @controller.protected()
    @validation.validated(schema.credential_create, 'credential')
    def create_credential(self, context, credential):
        trust_id = self._get_trust_id_for_request(context)
        ref = self._assign_unique_id(self._normalize_dict(credential),
                                     trust_id)
        ref = self.credential_api.create_credential(ref['id'], ref)
        return CredentialV3.wrap_member(context, ref)

    @staticmethod
    def _blob_to_json(ref):
        # credentials stored via ec2tokens before the fix for #1259584
        # need json serializing, as that's the documented API format
        blob = ref.get('blob')
        if isinstance(blob, dict):
            new_ref = ref.copy()
            new_ref['blob'] = jsonutils.dumps(blob)
            return new_ref
        else:
            return ref

    @controller.filterprotected('user_id', 'type')
    def list_credentials(self, context, filters):
        hints = CredentialV3.build_driver_hints(context, filters)
        refs = self.credential_api.list_credentials(hints)
        ret_refs = [self._blob_to_json(r) for r in refs]
        return CredentialV3.wrap_collection(context, ret_refs,
                                            hints=hints)

    @controller.protected()
    def get_credential(self, context, credential_id):
        ref = self.credential_api.get_credential(credential_id)
        ret_ref = self._blob_to_json(ref)
        return CredentialV3.wrap_member(context, ret_ref)

    @controller.protected()
    @validation.validated(schema.credential_update, 'credential')
    def update_credential(self, context, credential_id, credential):
        self._require_matching_id(credential_id, credential)

        ref = self.credential_api.update_credential(credential_id, credential)
        return CredentialV3.wrap_member(context, ref)

    @controller.protected()
    def delete_credential(self, context, credential_id):
        return self.credential_api.delete_credential(credential_id)

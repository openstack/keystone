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
import six

from oslo_serialization import jsonutils

from keystone.common import controller
from keystone.common import provider_api
from keystone.common import validation
from keystone.credential import schema
from keystone import exception
from keystone.i18n import _


PROVIDERS = provider_api.ProviderAPIs


class CredentialV3(controller.V3Controller):
    collection_name = 'credentials'
    member_name = 'credential'

    def __init__(self):
        super(CredentialV3, self).__init__()
        self.get_member_from_driver = PROVIDERS.credential_api.get_credential

    def _validate_blob_json(self, ref):
        try:
            blob = jsonutils.loads(ref.get('blob'))
        except (ValueError, TabError):
            raise exception.ValidationError(
                message=_('Invalid blob in credential'))
        if not blob or not isinstance(blob, dict):
            raise exception.ValidationError(attribute='blob',
                                            target='credential')
        if blob.get('access') is None:
            raise exception.ValidationError(attribute='access',
                                            target='credential')
        return blob

    def _assign_unique_id(
            self, ref, trust_id=None, app_cred_id=None, access_token_id=None):
        # Generates and assigns a unique identifier to a credential reference.
        if ref.get('type', '').lower() == 'ec2':
            blob = self._validate_blob_json(ref)
            ret_ref = ref.copy()
            ret_ref['id'] = hashlib.sha256(
                blob['access'].encode('utf8')).hexdigest()
            # update the blob with the trust_id,  so credentials
            # created with a trust- token will result in
            # trust- cred-scoped tokens when authentication via
            # ec2tokens happens
            if trust_id is not None:
                blob['trust_id'] = trust_id
                ret_ref['blob'] = jsonutils.dumps(blob)
            if app_cred_id is not None:
                blob['app_cred_id'] = app_cred_id
                ret_ref['blob'] = jsonutils.dumps(blob)
            if access_token_id is not None:
                blob['access_token_id'] = access_token_id
                ret_ref['blob'] = jsonutils.dumps(blob)
            return ret_ref
        else:
            return super(CredentialV3, self)._assign_unique_id(ref)

    @controller.protected()
    def create_credential(self, request, credential):
        validation.lazy_validate(schema.credential_create, credential)
        trust_id = request.context.trust_id
        access_token_id = request.context.oauth_access_token_id
        app_cred_id = request.auth_context['token'].get(
            'application_credential', {}).get('id')
        ref = self._assign_unique_id(self._normalize_dict(credential),
                                     trust_id=trust_id,
                                     app_cred_id=app_cred_id,
                                     access_token_id=access_token_id)
        ref = PROVIDERS.credential_api.create_credential(
            ref['id'], ref, initiator=request.audit_initiator)
        return CredentialV3.wrap_member(request.context_dict, ref)

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
    def list_credentials(self, request, filters):
        hints = CredentialV3.build_driver_hints(request, filters)
        refs = PROVIDERS.credential_api.list_credentials(hints)
        ret_refs = [self._blob_to_json(r) for r in refs]
        return CredentialV3.wrap_collection(request.context_dict, ret_refs,
                                            hints=hints)

    @controller.protected()
    def get_credential(self, request, credential_id):
        ref = PROVIDERS.credential_api.get_credential(credential_id)
        ret_ref = self._blob_to_json(ref)
        return CredentialV3.wrap_member(request.context_dict, ret_ref)

    def _validate_blob_update_keys(self, credential, ref):
        if credential.get('type', '').lower() == 'ec2':
            new_blob = self._validate_blob_json(ref)
            old_blob = credential.get('blob')
            if isinstance(old_blob, six.string_types):
                old_blob = jsonutils.loads(old_blob)
            # if there was a scope set, prevent changing it or unsetting it
            for key in ['trust_id', 'app_cred_id', 'access_token_id']:
                if old_blob.get(key) != new_blob.get(key):
                    message = _('%s can not be updated for credential') % key
                    raise exception.ValidationError(message=message)

    @controller.protected()
    def update_credential(self, request, credential_id, credential):
        current = self.credential_api.get_credential(credential_id)
        validation.lazy_validate(schema.credential_update, credential)
        self._validate_blob_update_keys(current.copy(), credential.copy())
        self._require_matching_id(credential_id, credential)
        # Check that the user hasn't illegally modified the owner or scope
        target = {'credential': dict(current, **credential)}
        prep_info = {'f_name': 'update_credential',
                     'input_attr': {}}
        self.check_protection(
            request, prep_info, target_attr=target
        )
        ref = PROVIDERS.credential_api.update_credential(
            credential_id, credential
        )
        return CredentialV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_credential(self, request, credential_id):
        return (PROVIDERS.credential_api.delete_credential(credential_id,
                initiator=request.audit_initiator))

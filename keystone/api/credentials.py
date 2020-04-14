#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This file handles all flask-restful resources for /v3/credentials

import hashlib
import six

import flask
from oslo_serialization import jsonutils
from six.moves import http_client

from keystone.common import provider_api
from keystone.common import rbac_enforcer
from keystone.common import validation
from keystone.credential import schema
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask


PROVIDERS = provider_api.ProviderAPIs
ENFORCER = rbac_enforcer.RBACEnforcer


def _build_target_enforcement():
    target = {}
    try:
        target['credential'] = PROVIDERS.credential_api.get_credential(
            flask.request.view_args.get('credential_id')
        )
    except exception.NotFound:  # nosec
        # Defer existance in the event the credential doesn't exist, we'll
        # check this later anyway.
        pass

    return target


class CredentialResource(ks_flask.ResourceBase):
    collection_key = 'credentials'
    member_key = 'credential'

    @staticmethod
    def _blob_to_json(ref):
        # credentials stored via ec2tokens before the fix for #1259584
        # need json_serailzing, as that's the documented API format
        blob = ref.get('blob')
        if isinstance(blob, dict):
            ref = ref.copy()
            ref['blob'] = jsonutils.dumps(blob)
        return ref

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
        # Generates an assigns a unique identifier to a credential reference.
        if ref.get('type', '').lower() == 'ec2':
            blob = self._validate_blob_json(ref)
            ref = ref.copy()
            ref['id'] = hashlib.sha256(
                blob['access'].encode('utf8')).hexdigest()
            # update the blob with the trust_id or app_cred_id, so credentials
            # created with a trust- or app cred-scoped token will result in
            # trust- or app cred-scoped tokens when authentication via
            # ec2tokens happens
            if trust_id is not None:
                blob['trust_id'] = trust_id
                ref['blob'] = jsonutils.dumps(blob)
            if app_cred_id is not None:
                blob['app_cred_id'] = app_cred_id
                ref['blob'] = jsonutils.dumps(blob)
            if access_token_id is not None:
                blob['access_token_id'] = access_token_id
                ref['blob'] = jsonutils.dumps(blob)
            return ref
        else:
            return super(CredentialResource, self)._assign_unique_id(ref)

    def _list_credentials(self):
        filters = ['user_id', 'type']
        ENFORCER.enforce_call(action='identity:list_credentials',
                              filters=filters)
        hints = self.build_driver_hints(filters)
        refs = PROVIDERS.credential_api.list_credentials(hints)
        refs = [self._blob_to_json(r) for r in refs]
        return self.wrap_collection(refs, hints=hints)

    def _get_credential(self, credential_id):
        ENFORCER.enforce_call(
            action='identity:get_credential',
            target_attr=_build_target_enforcement()
        )
        ref = PROVIDERS.credential_api.get_credential(credential_id)
        return self.wrap_member(self._blob_to_json(ref))

    def get(self, credential_id=None):
        # Get Credential or List of credentials.
        if credential_id is None:
            # No Parameter passed means that we're doing a LIST action.
            return self._list_credentials()
        else:
            return self._get_credential(credential_id)

    def post(self):
        # Create a new credential
        ENFORCER.enforce_call(action='identity:create_credential')
        credential = flask.request.json.get('credential', {})
        validation.lazy_validate(schema.credential_create, credential)
        trust_id = getattr(self.oslo_context, 'trust_id', None)
        app_cred_id = getattr(
            self.auth_context['token'], 'application_credential_id', None)
        access_token_id = getattr(
            self.auth_context['token'], 'access_token_id', None)
        ref = self._assign_unique_id(
            self._normalize_dict(credential),
            trust_id=trust_id, app_cred_id=app_cred_id,
            access_token_id=access_token_id)
        ref = PROVIDERS.credential_api.create_credential(
            ref['id'], ref, initiator=self.audit_initiator)
        return self.wrap_member(ref), http_client.CREATED

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

    def patch(self, credential_id):
        # Update Credential
        ENFORCER.enforce_call(
            action='identity:update_credential',
            target_attr=_build_target_enforcement()
        )
        current = PROVIDERS.credential_api.get_credential(credential_id)

        credential = flask.request.json.get('credential', {})
        validation.lazy_validate(schema.credential_update, credential)
        self._validate_blob_update_keys(current.copy(), credential.copy())
        self._require_matching_id(credential)
        # Check that the user hasn't illegally modified the owner or scope
        target = {'credential': dict(current, **credential)}
        ENFORCER.enforce_call(
            action='identity:update_credential', target_attr=target
        )
        ref = PROVIDERS.credential_api.update_credential(
            credential_id, credential)
        return self.wrap_member(ref)

    def delete(self, credential_id):
        # Delete credentials
        ENFORCER.enforce_call(
            action='identity:delete_credential',
            target_attr=_build_target_enforcement()
        )

        return (PROVIDERS.credential_api.delete_credential(credential_id,
                initiator=self.audit_initiator),
                http_client.NO_CONTENT)


class CredentialAPI(ks_flask.APIBase):

    _name = 'credentials'
    _import_name = __name__
    resource_mapping = []
    resources = [CredentialResource]


APIs = (CredentialAPI,)

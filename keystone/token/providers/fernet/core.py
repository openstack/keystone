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

import os


from keystone.common import utils as ks_utils
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.token.providers import base
from keystone.token import token_formatters as tf


CONF = keystone.conf.CONF


class Provider(base.Provider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)

        # NOTE(lbragstad): We add these checks here because if the fernet
        # provider is going to be used and either the `key_repository` is empty
        # or doesn't exist we should fail, hard. It doesn't make sense to start
        # keystone and just 500 because we can't do anything with an empty or
        # non-existant key repository.
        if not os.path.exists(CONF.fernet_tokens.key_repository):
            subs = {'key_repo': CONF.fernet_tokens.key_repository}
            raise SystemExit(_('%(key_repo)s does not exist') % subs)
        if not os.listdir(CONF.fernet_tokens.key_repository):
            subs = {'key_repo': CONF.fernet_tokens.key_repository}
            raise SystemExit(_('%(key_repo)s does not contain keys, use '
                               'keystone-manage fernet_setup to create '
                               'Fernet keys.') % subs)

        self.token_formatter = tf.TokenFormatter()

    def generate_id_and_issued_at(self, token):
        token_id = self.token_formatter.create_token(
            token.user_id,
            token.expires_at,
            token.audit_ids,
            methods=token.methods,
            system=token.system,
            domain_id=token.domain_id,
            project_id=token.project_id,
            trust_id=token.trust_id,
            federated_group_ids=token.federated_groups,
            identity_provider_id=token.identity_provider_id,
            protocol_id=token.protocol_id,
            access_token_id=token.access_token_id,
            app_cred_id=token.application_credential_id
        )
        creation_datetime_obj = self.token_formatter.creation_time(token_id)
        issued_at = ks_utils.isotime(
            at=creation_datetime_obj, subsecond=True
        )
        return token_id, issued_at

    def validate_token(self, token_id):
        try:
            return self.token_formatter.validate_token(token_id)
        except exception.ValidationError as e:
            raise exception.TokenNotFound(e)

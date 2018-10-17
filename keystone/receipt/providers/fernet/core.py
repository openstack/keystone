# Copyright 2018 Catalyst Cloud Ltd
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

import os


from keystone.common import utils as ks_utils
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.receipt.providers import base
from keystone.receipt import receipt_formatters as tf


CONF = keystone.conf.CONF


class Provider(base.Provider):
    def __init__(self, *args, **kwargs):
        super(Provider, self).__init__(*args, **kwargs)

        # NOTE(lbragstad): We add these checks here because if the fernet
        # provider is going to be used and either the `key_repository` is empty
        # or doesn't exist we should fail, hard. It doesn't make sense to start
        # keystone and just 500 because we can't do anything with an empty or
        # non-existant key repository.
        if not os.path.exists(CONF.fernet_receipts.key_repository):
            subs = {'key_repo': CONF.fernet_receipts.key_repository}
            raise SystemExit(_('%(key_repo)s does not exist') % subs)
        if not os.listdir(CONF.fernet_receipts.key_repository):
            subs = {'key_repo': CONF.fernet_receipts.key_repository}
            raise SystemExit(_('%(key_repo)s does not contain keys, use '
                               'keystone-manage fernet_setup to create '
                               'Fernet keys.') % subs)

        self.receipt_formatter = tf.ReceiptFormatter()

    def validate_receipt(self, receipt_id):
        try:
            return self.receipt_formatter.validate_receipt(receipt_id)
        except exception.ValidationError:
            raise exception.ReceiptNotFound(receipt_id=receipt_id)

    def generate_id_and_issued_at(self, receipt):
        receipt_id = self.receipt_formatter.create_receipt(
            receipt.user_id,
            receipt.methods,
            receipt.expires_at,
        )
        creation_datetime_obj = self.receipt_formatter.creation_time(
            receipt_id)
        issued_at = ks_utils.isotime(
            at=creation_datetime_obj, subsecond=True
        )
        return receipt_id, issued_at

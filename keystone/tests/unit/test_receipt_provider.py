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

import datetime
import uuid

from oslo_utils import timeutils

import freezegun
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.models import receipt_model
from keystone import receipt
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

DELTA = datetime.timedelta(seconds=CONF.receipt.expiration)
CURRENT_DATE = timeutils.utcnow()


class TestReceiptProvider(unit.TestCase):
    def setUp(self):
        super(TestReceiptProvider, self).setUp()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_receipts',
                CONF.fernet_receipts.max_active_keys
            )
        )
        self.load_backends()

    def test_unsupported_receipt_provider(self):
        self.config_fixture.config(group='receipt',
                                   provider='MyProvider')
        self.assertRaises(ImportError,
                          receipt.provider.Manager)

    def test_provider_receipt_expiration_validation(self):
        receipt = receipt_model.ReceiptModel()
        receipt.issued_at = utils.isotime(CURRENT_DATE)
        receipt.expires_at = utils.isotime(CURRENT_DATE - DELTA)
        receipt.id = uuid.uuid4().hex
        with freezegun.freeze_time(CURRENT_DATE):
            self.assertRaises(exception.ReceiptNotFound,
                              PROVIDERS.receipt_provider_api._is_valid_receipt,
                              receipt)

        # confirm a non-expired receipt doesn't throw errors.
        # returning None, rather than throwing an error is correct.
        receipt = receipt_model.ReceiptModel()
        receipt.issued_at = utils.isotime(CURRENT_DATE)
        receipt.expires_at = utils.isotime(CURRENT_DATE + DELTA)
        receipt.id = uuid.uuid4().hex
        with freezegun.freeze_time(CURRENT_DATE):
            self.assertIsNone(
                PROVIDERS.receipt_provider_api._is_valid_receipt(receipt))

    def test_validate_v3_none_receipt_raises_receipt_not_found(self):
        self.assertRaises(
            exception.ReceiptNotFound,
            PROVIDERS.receipt_provider_api.validate_receipt,
            None)

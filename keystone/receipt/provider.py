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

"""Receipt provider interface."""

import datetime

from oslo_log import log
from oslo_utils import timeutils

from keystone.common import cache
from keystone.common import manager
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.models import receipt_model
from keystone import notifications


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs

RECEIPTS_REGION = cache.create_region(name='receipts')
MEMOIZE_RECEIPTS = cache.get_memoization_decorator(
    group='receipt',
    region=RECEIPTS_REGION)


def default_expire_time():
    """Determine when a fresh receipt should expire.

    Expiration time varies based on configuration (see
    ``[receipt] expiration``).

    :returns: a naive UTC datetime.datetime object

    """
    expire_delta = datetime.timedelta(seconds=CONF.receipt.expiration)
    expires_at = timeutils.utcnow() + expire_delta
    return expires_at.replace(microsecond=0)


class Manager(manager.Manager):
    """Default pivot point for the receipt provider backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    driver_namespace = 'keystone.receipt.provider'
    _provides_api = 'receipt_provider_api'

    def __init__(self):
        super(Manager, self).__init__(CONF.receipt.provider)
        self._register_callback_listeners()

    def _register_callback_listeners(self):
        callbacks = {
            notifications.ACTIONS.deleted: [
                ['OS-TRUST:trust', self._drop_receipt_cache],
                ['user', self._drop_receipt_cache],
                ['domain', self._drop_receipt_cache],
            ],
            notifications.ACTIONS.disabled: [
                ['user', self._drop_receipt_cache],
                ['domain', self._drop_receipt_cache],
                ['project', self._drop_receipt_cache],
            ],
            notifications.ACTIONS.internal: [
                [notifications.INVALIDATE_TOKEN_CACHE,
                    self._drop_receipt_cache],
            ]
        }

        for event, cb_info in callbacks.items():
            for resource_type, callback_fns in cb_info:
                notifications.register_event_callback(event, resource_type,
                                                      callback_fns)

    def _drop_receipt_cache(self, service, resource_type, operation, payload):
        """Invalidate the entire receipt cache.

        This is a handy private utility method that should be used when
        consuming notifications that signal invalidating the receipt cache.

        """
        if CONF.receipt.cache_on_issue:
            RECEIPTS_REGION.invalidate()

    def validate_receipt(self, receipt_id, window_seconds=0):
        if not receipt_id:
            raise exception.ReceiptNotFound(
                _('No receipt in the request'), receipt_id=receipt_id)

        try:
            receipt = self._validate_receipt(receipt_id)
            self._is_valid_receipt(receipt, window_seconds=window_seconds)
            return receipt
        except exception.Unauthorized as e:
            LOG.debug('Unable to validate receipt: %s', e)
            raise exception.ReceiptNotFound(receipt_id=receipt_id)

    @MEMOIZE_RECEIPTS
    def _validate_receipt(self, receipt_id):
        (user_id, methods, issued_at,
            expires_at) = self.driver.validate_receipt(receipt_id)

        receipt = receipt_model.ReceiptModel()
        receipt.user_id = user_id
        receipt.methods = methods
        receipt.expires_at = expires_at
        receipt.mint(receipt_id, issued_at)
        return receipt

    def _is_valid_receipt(self, receipt, window_seconds=0):
        """Verify the receipt is valid format and has not expired."""
        current_time = timeutils.normalize_time(timeutils.utcnow())

        try:
            expiry = timeutils.parse_isotime(receipt.expires_at)
            expiry = timeutils.normalize_time(expiry)

            # add a window in which you can fetch a receipt beyond expiry
            expiry += datetime.timedelta(seconds=window_seconds)

        except Exception:
            LOG.exception('Unexpected error or malformed receipt '
                          'determining receipt expiry: %s', receipt)
            raise exception.ReceiptNotFound(
                _('Failed to validate receipt'), receipt_id=receipt.id)

        if current_time < expiry:
            return None
        else:
            raise exception.ReceiptNotFound(
                _('Failed to validate receipt'), receipt_id=receipt.id)

    def issue_receipt(self, user_id, method_names, expires_at=None):

        receipt = receipt_model.ReceiptModel()
        receipt.user_id = user_id
        receipt.methods = method_names

        if isinstance(expires_at, datetime.datetime):
            receipt.expires_at = utils.isotime(expires_at, subsecond=True)
        if isinstance(expires_at, str):
            receipt.expires_at = expires_at
        elif not expires_at:
            receipt.expires_at = utils.isotime(
                default_expire_time(), subsecond=True
            )

        receipt_id, issued_at = self.driver.generate_id_and_issued_at(receipt)
        receipt.mint(receipt_id, issued_at)

        if CONF.receipt.cache_on_issue:
            self._validate_receipt.set(
                receipt, RECEIPTS_REGION, receipt_id)

        return receipt

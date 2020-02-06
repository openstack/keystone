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

import abc

from keystone import exception


class Provider(object, metaclass=abc.ABCMeta):
    """Interface description for a Receipt provider."""

    @abc.abstractmethod
    def validate_receipt(self, receipt_id):
        """Validate a given receipt by its ID and return the receipt_data.

        :param receipt_id: the unique ID of the receipt
        :type receipt_id: str
        :returns: receipt data as a tuple in the form of:

        (user_id, methods, issued_at, expires_at)

        ``user_id`` is the unique ID of the user as a string
        ``methods`` a list of authentication methods used to obtain the receipt
        ``issued_at`` a datetime object of when the receipt was minted
        ``expires_at`` a datetime object of when the receipt expires

        :raises keystone.exception.ReceiptNotFound: when receipt doesn't exist.
        """

    @abc.abstractmethod
    def generate_id_and_issued_at(self, receipt):
        """Generate a receipt based on the information provided.

        :param receipt: A receipt object containing information about the
                        authorization context of the request.
        :type receipt: `keystone.models.receipt.ReceiptModel`
        :returns: tuple containing an ID for the receipt and the issued at time
                  of the receipt (receipt_id, issued_at).
        """
        raise exception.NotImplemented()  # pragma: no cover

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

"""Unified in-memory receipt model."""

from oslo_log import log
from oslo_serialization import msgpackutils
from oslo_utils import reflection

from keystone.auth import core
from keystone.common import cache
from keystone.common import provider_api
from keystone import exception
from keystone.identity.backends import resource_options as ro

LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class ReceiptModel(object):
    """An object that represents a receipt emitted by keystone.

    This is a queryable object that other parts of keystone can use to reason
    about a user's receipt.
    """

    def __init__(self):
        self.user_id = None
        self.__user = None
        self.__user_domain = None

        self.methods = None
        self.__required_methods = None

        self.__expires_at = None
        self.__issued_at = None

    def __repr__(self):
        """Return string representation of KeystoneReceipt."""
        desc = ('<%(type)s at %(loc)s>')
        self_cls_name = reflection.get_class_name(self, fully_qualified=False)
        return desc % {'type': self_cls_name, 'loc': hex(id(self))}

    @property
    def expires_at(self):
        return self.__expires_at

    @expires_at.setter
    def expires_at(self, value):
        if not isinstance(value, str):
            raise ValueError('expires_at must be a string.')
        self.__expires_at = value

    @property
    def issued_at(self):
        return self.__issued_at

    @issued_at.setter
    def issued_at(self, value):
        if not isinstance(value, str):
            raise ValueError('issued_at must be a string.')
        self.__issued_at = value

    @property
    def user(self):
        if not self.__user:
            if self.user_id:
                self.__user = PROVIDERS.identity_api.get_user(self.user_id)
        return self.__user

    @property
    def user_domain(self):
        if not self.__user_domain:
            if self.user:
                self.__user_domain = PROVIDERS.resource_api.get_domain(
                    self.user['domain_id']
                )
        return self.__user_domain

    @property
    def required_methods(self):
        if not self.__required_methods:
            mfa_rules = self.user['options'].get(
                ro.MFA_RULES_OPT.option_name, [])
            rules = core.UserMFARulesValidator._parse_rule_structure(
                mfa_rules, self.user_id)
            methods = set(self.methods)
            active_methods = set(core.AUTH_METHODS.keys())

            required_auth_methods = []
            for r in rules:
                r_set = set(r).intersection(active_methods)
                if r_set.intersection(methods):
                    required_auth_methods.append(list(r_set))

            self.__required_methods = required_auth_methods

        return self.__required_methods

    def mint(self, receipt_id, issued_at):
        """Set the ``id`` and ``issued_at`` attributes of a receipt.

        The process of building a Receipt requires setting attributes about the
        partial authentication context, like ``user_id`` and ``methods`` for
        example. Once a Receipt object accurately represents this information
        it should be "minted". Receipt are minted when they get an ``id``
        attribute and their creation time is recorded.
        """
        self.id = receipt_id
        self.issued_at = issued_at


class _ReceiptModelHandler(object):
    identity = 125
    handles = (ReceiptModel,)

    def __init__(self, registry):
        self._registry = registry

    def serialize(self, obj):
        serialized = msgpackutils.dumps(obj.__dict__, registry=self._registry)
        return serialized

    def deserialize(self, data):
        receipt_data = msgpackutils.loads(data, registry=self._registry)
        try:
            receipt_model = ReceiptModel()
            for k, v in iter(receipt_data.items()):
                setattr(receipt_model, k, v)
        except Exception:
            LOG.debug(
                "Failed to deserialize ReceiptModel. Data is %s", receipt_data
            )
            raise exception.CacheDeserializationError(
                ReceiptModel.__name__, receipt_data
            )
        return receipt_model


cache.register_model_handler(_ReceiptModelHandler)

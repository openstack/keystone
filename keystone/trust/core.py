# Copyright 2012 OpenStack Foundation
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

"""Main entry point into the Identity service."""

import abc

import six

from keystone.common import dependency
from keystone.common import manager
from keystone import config
from keystone import exception
from keystone import notifications
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log


CONF = config.CONF

LOG = log.getLogger(__name__)


@dependency.provider('trust_api')
class Manager(manager.Manager):
    """Default pivot point for the Trust backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """
    _TRUST = "OS-TRUST:trust"

    def __init__(self):
        super(Manager, self).__init__(CONF.trust.driver)

    @notifications.created(_TRUST)
    def create_trust(self, trust_id, trust, roles):
        """Create a new trust.

        :returns: a new trust
        """
        trust.setdefault('remaining_uses', None)
        if trust['remaining_uses'] is not None:
            if (trust['remaining_uses'] <= 0 or
                    not isinstance(trust['remaining_uses'], int)):
                msg = _('remaining_uses must be a positive integer or null.')
                raise exception.ValidationError(msg)
        return self.driver.create_trust(trust_id, trust, roles)

    @notifications.deleted(_TRUST)
    def delete_trust(self, trust_id):
        """Remove a trust.

        :raises: keystone.exception.TrustNotFound
        """
        self.driver.delete_trust(trust_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    @abc.abstractmethod
    def create_trust(self, trust_id, trust, roles):
        """Create a new trust.

        :returns: a new trust
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_trust(self, trust_id):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_trusts(self):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_trusts_for_trustee(self, trustee):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_trusts_for_trustor(self, trustor):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_trust(self, trust_id):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def consume_use(self, trust_id):
        """Consume one use when a trust was created with a limitation on its
        uses, provided there are still uses available.

        :raises: keystone.exception.TrustUseLimitReached,
                 keystone.exception.TrustNotFound
        """
        raise exception.NotImplemented()

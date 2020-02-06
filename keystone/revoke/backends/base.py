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

import abc
import datetime

from oslo_utils import timeutils

import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


def revoked_before_cutoff_time():
    expire_delta = datetime.timedelta(
        seconds=CONF.token.expiration + CONF.revoke.expiration_buffer)
    oldest = timeutils.utcnow() - expire_delta
    return oldest


class RevokeDriverBase(object, metaclass=abc.ABCMeta):
    """Interface for recording and reporting revocation events."""

    @abc.abstractmethod
    def list_events(self, last_fetch=None, token=None):
        """return the revocation events, as a list of objects.

        :param last_fetch:   Time of last fetch.  Return all events newer.
        :param token: dictionary of values from a token, normalized for
                      differences between v2 and v3. The checked values are a
                      subset of the attributes of model.TokenEvent
        :returns: A list of keystone.revoke.model.RevokeEvent
                  newer than `last_fetch.`
                  If no last_fetch is specified, returns all events
                  for tokens issued after the expiration cutoff.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def revoke(self, event):
        """register a revocation event.

        :param event: An instance of
            keystone.revoke.model.RevocationEvent

        """
        raise exception.NotImplemented()  # pragma: no cover

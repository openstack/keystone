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

from keystone import exception


class TrustDriverBase(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_trust(self, trust_id, trust, roles):
        """Create a new trust.

        :returns: a new trust
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_trust(self, trust_id, deleted=False):
        """Get a trust by the trust id.

        :param trust_id: the trust identifier
        :type trust_id: string
        :param deleted: return the trust even if it is deleted, expired, or
                        has no consumptions left
        :type deleted: bool
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_trusts(self):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_trusts_for_trustee(self, trustee):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_trusts_for_trustor(self, trustor, redelegated_trust_id=None):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_trust(self, trust_id):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def consume_use(self, trust_id):
        """Consume one use of a trust.

        One use of a trust is consumed when the trust was created with a
        limitation on its uses, provided there are still uses available.

        :raises keystone.exception.TrustUseLimitReached: If no remaining uses
            for trust.
        :raises keystone.exception.TrustNotFound: If the trust doesn't exist.
        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_trusts_for_project(self, project_id):
        """Delete all trusts for a project.

        :param project_id: ID of a project to filter trusts by.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def flush_expired_and_soft_deleted_trusts(self, project_id=None,
                                              trustor_user_id=None,
                                              trustee_user_id=None,
                                              date=None):
        """Flush expired and non-expired soft deleted trusts from the backend.

        :param project_id: ID of a project to filter trusts by.
        :param trustor_user_id: ID of a trustor_user_id to filter trusts by.
        :param trustee_user_id: ID of a trustee_user_id to filter trusts by.
        :param date: date to filter trusts by.
        :type date: datetime

        """
        raise exception.NotImplemented()  # pragma: no cover

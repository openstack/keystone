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

from oslo_log import versionutils
import six

from keystone import exception


@six.add_metaclass(abc.ABCMeta)
class ShadowUsersDriverBase(object):
    """Interface description for an Shadow Users driver."""

    @abc.abstractmethod
    def create_federated_user(self, federated_dict):
        """Create a new user with the federated identity.

        :param dict federated_dict: Reference to the federated user
        :param user_id: user ID for linking to the federated identity
        :returns dict: Containing the user reference

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_federated_user(self, idp_id, protocol_id, unique_id):
        """Return the found user for the federated identity.

        :param idp_id: The identity provider ID
        :param protocol_id: The federation protocol ID
        :param unique_id: The unique ID for the user
        :returns dict: Containing the user reference

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_federated_user_display_name(self, idp_id, protocol_id,
                                           unique_id, display_name):
        """Update federated user's display name if changed.

        :param idp_id: The identity provider ID
        :param protocol_id: The federation protocol ID
        :param unique_id: The unique ID for the user
        :param display_name: The user's display name

        """
        raise exception.NotImplemented()


@versionutils.deprecated(
    versionutils.deprecated.NEWTON,
    what='keystone.identity.shadow_backends.base.ShadowUsersDriverV9',
    in_favor_of='keystone.identity.shadow_backends.base.ShadowUsersDriverV10',
    remove_in=+1)
class ShadowUsersDriverV9(ShadowUsersDriverBase):
    pass


@six.add_metaclass(abc.ABCMeta)
class ShadowUsersDriverV10(ShadowUsersDriverBase):
    """Interface description for an Shadow Users V10 driver."""

    @abc.abstractmethod
    def get_user(self, user_id):
        """Return the found user.

        :param user_id: Unique identifier of the user
        :returns dict: Containing the user reference

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_nonlocal_user(self, user_dict):
        """Create a new non-local user.

        :param dict user_dict: Reference to the non-local user
        :returns dict: Containing the user reference

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def set_last_active_at(self, user_id):
        """Set the last active at date for the user.

        :param user_id: Unique identifier of the user

        """
        raise exception.NotImplemented()


class V10ShadowUsersWrapperForV9Driver(ShadowUsersDriverV10):
    def get_user(self, user_id):
        raise exception.UserNotFound(user_id=user_id)

    def create_nonlocal_user(self, user_dict):
        return user_dict

    def set_last_active_at(self, user_id):
        pass

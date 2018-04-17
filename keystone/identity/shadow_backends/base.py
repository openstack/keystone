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

import six

from keystone import exception


@six.add_metaclass(abc.ABCMeta)
class ShadowUsersDriverBase(object):
    """Interface description for an Shadow Users driver."""

    @abc.abstractmethod
    def create_federated_user(self, domain_id, federated_dict, email=None):
        """Create a new user with the federated identity.

        :param domain_id: The domain ID of the IdP used for the federated user
        :param dict federated_dict: Reference to the federated user
        :param email: Federated user's email
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

    @abc.abstractmethod
    def list_federated_users_info(self, hints=None):
        """Get the shadow users info with the specified filters.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.
        :returns list: A list of objects that containing the shadow users
                       reference.

        """
        raise exception.NotImplemented()

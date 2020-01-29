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

import keystone.conf
from keystone import exception


CONF = keystone.conf.CONF


def filter_user(user_ref):
    """Filter out private items in a user dict.

    'password', 'tenants' and 'groups' are never returned.

    :returns: user_ref

    """
    if user_ref:
        user_ref = user_ref.copy()
        user_ref.pop('password', None)
        user_ref.pop('tenants', None)
        user_ref.pop('groups', None)
        user_ref.pop('domains', None)
        try:
            user_ref['extra'].pop('password', None)
            user_ref['extra'].pop('tenants', None)
        except KeyError:  # nosec
            # ok to not have extra in the user_ref.
            pass
        if 'password_expires_at' not in user_ref:
            user_ref['password_expires_at'] = None
    return user_ref


class IdentityDriverBase(object, metaclass=abc.ABCMeta):
    """Interface description for an Identity driver.

    The schema for users and groups is different depending on whether the
    driver is domain aware or not (as returned by self.is_domain_aware()).

    If the driver is not domain aware:

    * domain_id will be not be included in the user / group passed in to
      create_user / create_group
    * the domain_id should not be returned in user / group refs. They'll be
      overwritten.

    The password_expires_at in the user schema is a read-only attribute,
    meaning that it is expected in the response, but not in the request.

    User schema (if driver is domain aware)::

        type: object
        properties:
            id:
                type: string
            name:
                type: string
            domain_id:
                type: string
            password:
                type: string
            password_expires_at:
                type: datetime
            enabled:
                type: boolean
            default_project_id:
                type: string
        required: [id, name, domain_id, enabled]
        additionalProperties: True

    User schema (if driver is not domain aware)::

        type: object
        properties:
            id:
                type: string
            name:
                type: string
            password:
                type: string
            password_expires_at:
                type: datetime
            enabled:
                type: boolean
            default_project_id:
                type: string
        required: [id, name, enabled]
        additionalProperties: True
        # Note that domain_id is not allowed as a property

    Group schema (if driver is domain aware)::

        type: object
        properties:
            id:
                type: string
            name:
                type: string
            domain_id:
                type: string
            description:
                type: string
        required: [id, name, domain_id]
        additionalProperties: True

    Group schema (if driver is not domain aware)::

        type: object
        properties:
            id:
                type: string
            name:
                type: string
            description:
                type: string
        required: [id, name]
        additionalProperties: True
        # Note that domain_id is not allowed as a property

    """

    def _get_conf(self):
        try:
            return self.conf or CONF
        except AttributeError:
            return CONF

    def _get_list_limit(self):
        conf = self._get_conf()
        # use list_limit from domain-specific config. If list_limit in
        # domain-specific config is not set, look it up in the default config
        return (conf.identity.list_limit or conf.list_limit or
                CONF.identity.list_limit or CONF.list_limit)

    def is_domain_aware(self):
        """Indicate if the driver supports domains."""
        return True

    @property
    def is_sql(self):
        """Indicate if this Driver uses SQL."""
        return False

    @property
    def multiple_domains_supported(self):
        return (self.is_domain_aware() or
                CONF.identity.domain_specific_drivers_enabled)

    def generates_uuids(self):
        """Indicate if Driver generates UUIDs as the local entity ID."""
        return True

    @abc.abstractmethod
    def authenticate(self, user_id, password):
        """Authenticate a given user and password.

        :param str user_id: User ID
        :param str password: Password

        :returns: user. See user schema in :class:`~.IdentityDriverBase`.
        :rtype: dict

        :raises AssertionError: If user or password is invalid.
        """
        raise exception.NotImplemented()  # pragma: no cover

    # user crud

    @abc.abstractmethod
    def create_user(self, user_id, user):
        """Create a new user.

        :param str user_id: user ID. The driver can ignore this value.
        :param dict user: user info. See user schema in
                          :class:`~.IdentityDriverBase`.

        :returns: user, matching the user schema. The driver should not return
                  the password.
        :rtype: dict

        :raises keystone.exception.Conflict: If a duplicate user exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_users(self, hints):
        """List users in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.
        :type hints: keystone.common.driver_hints.Hints

        :returns: a list of users or an empty list. See user schema in
                  :class:`~.IdentityDriverBase`.
        :rtype: list of dict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def unset_default_project_id(self, project_id):
        """Unset a user's default project given a specific project ID.

        :param str project_id: project ID

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_users_in_group(self, group_id, hints):
        """List users in a group.

        :param str group_id: the group in question
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :type hints: keystone.common.driver_hints.Hints

        :returns: a list of users or an empty list. See user schema in
                  :class:`~.IdentityDriverBase`.
        :rtype: list of dict

        :raises keystone.exception.GroupNotFound: If the group doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user(self, user_id):
        """Get a user by ID.

        :param str user_id: User ID.

        :returns: user. See user schema in :class:`~.IdentityDriverBase`.
        :rtype: dict

        :raises keystone.exception.UserNotFound: If the user doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_user(self, user_id, user):
        """Update an existing user.

        :param str user_id: User ID.
        :param dict user: User modification. See user schema in
            :class:`~.IdentityDriverBase`. Properties set to None will be
            removed. Required properties cannot be removed.

        :returns: user. See user schema in :class:`~.IdentityDriverBase`.

        :raises keystone.exception.UserNotFound: If the user doesn't exist.
        :raises keystone.exception.Conflict: If a duplicate user exists in the
            same domain.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def change_password(self, user_id, new_password):
        """Self-service password change.

        :param str user_id: User ID.
        :param str new_password: New password.

        :raises keystone.exception.UserNotFound: If the user doesn't exist.
        :raises keystone.exception.PasswordValidation: If password fails
            validation

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_user_to_group(self, user_id, group_id):
        """Add a user to a group.

        :param str user_id: User ID.
        :param str group_id: Group ID.

        :raises keystone.exception.UserNotFound: If the user doesn't exist.
        :raises keystone.exception.GroupNotFound: If the group doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def check_user_in_group(self, user_id, group_id):
        """Check if a user is a member of a group.

        :param str user_id: User ID.
        :param str group_id: Group ID.

        :raises keystone.exception.NotFound: If the user is not a member of the
                                             group.
        :raises keystone.exception.UserNotFound: If the user doesn't exist.
        :raises keystone.exception.GroupNotFound: If the group doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def remove_user_from_group(self, user_id, group_id):
        """Remove a user from a group.

        :param str user_id: User ID.
        :param str group_id: Group ID.

        :raises keystone.exception.NotFound: If the user is not in the group.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_user(self, user_id):
        """Delete an existing user.

        :raises keystone.exception.UserNotFound: If the user doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_user_by_name(self, user_name, domain_id):
        """Get a user by name.

        :returns: user_ref
        :raises keystone.exception.UserNotFound: If the user doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    # group crud

    @abc.abstractmethod
    def create_group(self, group_id, group):
        """Create a new group.

        :param str group_id: group ID. The driver can ignore this value.
        :param dict group: group info. See group schema in
                           :class:`~.IdentityDriverBase`.

        :returns: group, matching the group schema.
        :rtype: dict

        :raises keystone.exception.Conflict: If a duplicate group exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups(self, hints):
        """List groups in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.
        :type hints: keystone.common.driver_hints.Hints

        :returns: a list of group_refs or an empty list. See group schema in
                  :class:`~.IdentityDriverBase`.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_groups_for_user(self, user_id, hints):
        """List groups a user is in.

        :param str user_id: the user in question
        :param hints: filter hints which the driver should
                      implement if at all possible.
        :type hints: keystone.common.driver_hints.Hints

        :returns: a list of group_refs or an empty list. See group schema in
                  :class:`~.IdentityDriverBase`.

        :raises keystone.exception.UserNotFound: If the user doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group(self, group_id):
        """Get a group by ID.

        :param str group_id: group ID.

        :returns: group info. See group schema in :class:`~.IdentityDriverBase`
        :rtype: dict
        :raises keystone.exception.GroupNotFound: If the group doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_group_by_name(self, group_name, domain_id):
        """Get a group by name.

        :param str group_name: group name.
        :param str domain_id: domain ID.

        :returns: group info. See group schema in
            :class:`~.IdentityDriverBase`.
        :rtype: dict
        :raises keystone.exception.GroupNotFound: If the group doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_group(self, group_id, group):
        """Update an existing group.

        :param str group_id: Group ID.
        :param dict group: Group modification. See group schema in
            :class:`~.IdentityDriverBase`. Required properties cannot be
            removed.

        :returns: group, matching the group schema.
        :rtype: dict

        :raises keystone.exception.GroupNotFound: If the group doesn't exist.
        :raises keystone.exception.Conflict: If a duplicate group exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_group(self, group_id):
        """Delete an existing group.

        :param str group_id: Group ID.

        :raises keystone.exception.GroupNotFound: If the group doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

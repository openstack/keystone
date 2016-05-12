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

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
import six

from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
LOG = log.getLogger(__name__)


# The RoleDriverBase class is the set of driver methods from earlier
# drivers that we still support, that have not been removed or modified. This
# class is then used to created the augmented V8 and V9 version abstract driver
# classes, without having to duplicate a lot of abstract method signatures.
# If you remove a method from V9, then move the abstract methods from this Base
# class to the V8 class. Do not modify any of the method signatures in the Base
# class - changes should only be made in the V8 and subsequent classes.
@six.add_metaclass(abc.ABCMeta)
class RoleDriverBase(object):

    def _get_list_limit(self):
        return CONF.role.list_limit or CONF.list_limit

    @abc.abstractmethod
    def create_role(self, role_id, role):
        """Create a new role.

        :raises keystone.exception.Conflict: If a duplicate role exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_roles(self, hints):
        """List roles in the system.

        :param hints: filter hints which the driver should
                      implement if at all possible.

        :returns: a list of role_refs or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_roles_from_ids(self, role_ids):
        """List roles for the provided list of ids.

        :param role_ids: list of ids

        :returns: a list of role_refs.

        This method is used internally by the assignment manager to bulk read
        a set of roles given their ids.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_role(self, role_id):
        """Get a role by ID.

        :returns: role_ref
        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_role(self, role_id, role):
        """Update an existing role.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.
        :raises keystone.exception.Conflict: If a duplicate role exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_role(self, role_id):
        """Delete an existing role.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover


class RoleDriverV8(RoleDriverBase):
    """Removed or redefined methods from V8.

    Move the abstract methods of any methods removed or modified in later
    versions of the driver from RoleDriverBase to here. We maintain this
    so that legacy drivers, which will be a subclass of RoleDriverV8, can
    still reference them.

    """

    pass


class RoleDriverV9(RoleDriverBase):
    """New or redefined methods from V8.

    Add any new V9 abstract methods (or those with modified signatures) to
    this class.

    """

    @abc.abstractmethod
    def get_implied_role(self, prior_role_id, implied_role_id):
        """Get a role inference rule.

        :raises keystone.exception.ImpliedRoleNotFound: If the implied role
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_implied_role(self, prior_role_id, implied_role_id):
        """Create a role inference rule.

        :raises: keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_implied_role(self, prior_role_id, implied_role_id):
        """Delete a role inference rule.

        :raises keystone.exception.ImpliedRoleNotFound: If the implied role
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_role_inference_rules(self):
        """List all the rules used to imply one role from another."""
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_implied_roles(self, prior_role_id):
        """List roles implied from the prior role ID."""
        raise exception.NotImplemented()  # pragma: no cover


class V9RoleWrapperForV8Driver(RoleDriverV9):
    """Wrapper class to supported a V8 legacy driver.

    In order to support legacy drivers without having to make the manager code
    driver-version aware, we wrap legacy drivers so that they look like the
    latest version. For the various changes made in a new driver, here are the
    actions needed in this wrapper:

    Method removed from new driver - remove the call-through method from this
                                     class, since the manager will no longer be
                                     calling it.
    Method signature (or meaning) changed - wrap the old method in a new
                                            signature here, and munge the input
                                            and output parameters accordingly.
    New method added to new driver - add a method to implement the new
                                     functionality here if possible. If that is
                                     not possible, then return NotImplemented,
                                     since we do not guarantee to support new
                                     functionality with legacy drivers.

    This V8 wrapper contains the following support for newer manager code:

    - The current manager code expects a role entity to have a domain_id
      attribute, with a non-None value indicating a domain specific role. V8
      drivers will only understand global roles, hence if a non-None domain_id
      is passed to this wrapper, it will raise a NotImplemented exception.
      If a None-valued domain_id is passed in, it will be trimmed off before
      the underlying driver is called (and a None-valued domain_id attribute
      is added in for any entities returned to the manager.

    """

    @versionutils.deprecated(
        as_of=versionutils.deprecated.MITAKA,
        what='keystone.assignment.RoleDriverV8',
        in_favor_of='keystone.assignment.RoleDriverV9',
        remove_in=+2)
    def __init__(self, wrapped_driver):
        self.driver = wrapped_driver

    def _append_null_domain_id(self, role_or_list):
        def _append_null_domain_id_to_dict(role):
            if 'domain_id' not in role:
                role['domain_id'] = None
            return role

        if isinstance(role_or_list, list):
            return [_append_null_domain_id_to_dict(x) for x in role_or_list]
        else:
            return _append_null_domain_id_to_dict(role_or_list)

    def _trim_and_assert_null_domain_id(self, role):
        if 'domain_id' in role:
            if role['domain_id'] is not None:
                raise exception.NotImplemented(
                    _('Domain specific roles are not supported in the V8 '
                      'role driver'))
            else:
                new_role = role.copy()
                new_role.pop('domain_id')
                return new_role
        else:
            return role

    def create_role(self, role_id, role):
        new_role = self._trim_and_assert_null_domain_id(role)
        return self._append_null_domain_id(
            self.driver.create_role(role_id, new_role))

    def list_roles(self, hints):
        return self._append_null_domain_id(self.driver.list_roles(hints))

    def list_roles_from_ids(self, role_ids):
        return self._append_null_domain_id(
            self.driver.list_roles_from_ids(role_ids))

    def get_role(self, role_id):
        return self._append_null_domain_id(self.driver.get_role(role_id))

    def update_role(self, role_id, role):
        update_role = self._trim_and_assert_null_domain_id(role)
        return self._append_null_domain_id(
            self.driver.update_role(role_id, update_role))

    def delete_role(self, role_id):
        self.driver.delete_role(role_id)

    def get_implied_role(self, prior_role_id, implied_role_id):
        raise exception.NotImplemented()  # pragma: no cover

    def create_implied_role(self, prior_role_id, implied_role_id):
        raise exception.NotImplemented()  # pragma: no cover

    def delete_implied_role(self, prior_role_id, implied_role_id):
        raise exception.NotImplemented()  # pragma: no cover

    def list_implied_roles(self, prior_role_id):
        raise exception.NotImplemented()  # pragma: no cover

    def list_role_inference_rules(self):
        raise exception.NotImplemented()  # pragma: no cover

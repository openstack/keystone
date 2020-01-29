# Copyright 2017 SUSE Linux Gmbh
# Copyright 2017 Huawei
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


class UnifiedLimitDriverBase(object, metaclass=abc.ABCMeta):

    def _get_list_limit(self):
        return CONF.unified_limit.list_limit or CONF.list_limit

    @abc.abstractmethod
    def create_registered_limits(self, registered_limits):
        """Create new registered limits.

        :param registered_limits: a list of dictionaries representing limits to
                                  create.

        :returns: all the newly created registered limits.
        :raises keystone.exception.Conflict: If a duplicate registered limit
            exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_registered_limit(self, registered_limit_id, registered_limit):
        """Update existing registered limits.

        :param registered_limit_id: the id of the registered limit.
        :param registered_limit: a dict containing the registered limit
                                 attributes to update.
        :returns: the updated registered limit.
        :raises keystone.exception.RegisteredLimitNotFound: If registered limit
            doesn't exist.
        :raises keystone.exception.Conflict: If update to a duplicate
            registered limit.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_registered_limits(self, hints):
        """List all registered limits.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: a list of dictionaries or an empty registered limit.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_registered_limit(self, registered_limit_id):
        """Get a registered limit.

        :param registered_limit_id: the registered limit id to get.

        :returns: a dictionary representing a registered limit reference.
        :raises keystone.exception.RegisteredLimitNotFound: If registered limit
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_registered_limit(self, registered_limit_id):
        """Delete an existing registered limit.

        :param registered_limit_id: the registered limit id to delete.

        :raises keystone.exception.RegisteredLimitNotFound: If registered limit
            doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def create_limits(self, limits):
        """Create new limits.

        :param limits: a list of dictionaries representing limits to create.

        :returns: all the newly created limits.
        :raises keystone.exception.Conflict: If a duplicate limit exists.
        :raises keystone.exception.NoLimitReference: If no reference registered
            limit exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_limit(self, limit_id, limit):
        """Update existing limits.

        :param limit_id: the id of the limit.
        :param limit: a dict containing the limit attributes to update.

        :returns: the updated limit.
        :raises keystone.exception.LimitNotFound: If limit doesn't
            exist.
        :raises keystone.exception.Conflict: If update to a duplicate limit.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def list_limits(self, hints):
        """List all limits.

        :param hints: contains the list of filters yet to be satisfied.
                      Any filters satisfied here will be removed so that
                      the caller will know if any filters remain.

        :returns: a list of dictionaries or an empty list.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_limit(self, limit_id):
        """Get a limit.

        :param limit_id: the limit id to get.

        :returns: a dictionary representing a limit reference.
        :raises keystone.exception.LimitNotFound: If limit doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_limit(self, limit_id):
        """Delete an existing limit.

        :param limit_id: the limit id to delete.

        :raises keystone.exception.LimitNotFound: If limit doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_limits_for_project(self, project_id):
        """Delete the existing limits which belong to the specified project.

        :param project_id: the limits' project id.

        :returns: a dictionary representing the deleted limits id. Used for
            cache invalidating.

        """
        raise exception.NotImplemented()  # pragma: no cover

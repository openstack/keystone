# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2011 OpenStack LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Role manager module """

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.ROLE

    def create(self, role):
        """ Create a new role """
        return self.driver.create(role)

    def get(self, role_id):
        """ Returns role by ID """
        return self.driver.get(role_id)

    def get_by_name(self, name):
        """ Returns role by name """
        return self.driver.get_by_name(name=name)

    def get_all(self):
        """ Returns all roles """
        return self.driver.get_all()

    def get_page(self, marker, limit):
        """ Get one page of roles list """
        return self.driver.get_page(marker, limit)

    def get_page_markers(self, marker, limit):
        """ Calculate pagination markers for roles list """
        return self.driver.get_page_markers(marker, limit)

    def get_by_service(self, service_id):
        """ Returns role by service """
        return self.driver.get_by_service(service_id)

    def get_by_service_get_page(self, service_id, marker, limit):
        """ Get one page of roles by service"""
        return self.driver.get_by_service_get_page(service_id, marker, limit)

    def get_by_service_get_page_markers(self, service_id, marker, limit):
        """ Calculate pagination markers for roles by service """
        return self.driver.get_by_service_get_page_markers(service_id, marker,
                limit)

    # pylint: disable=E1103
    def update(self, role):
        """ Update role """
        return self.driver.update(role['id'], role)

    def delete(self, role_id):
        """ Delete role """
        self.driver.delete(role_id)

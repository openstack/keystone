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

""" Service manager module """

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.SERVICE

    def create(self, service):
        """ Create a new service """
        return self.driver.create(service)

    def get(self, service_id):
        """ Returns service by ID """
        return self.driver.get(service_id)

    def get_by_name(self, name):
        """ Returns service by name """
        return self.driver.get_by_name(name=name)

    def get_all(self):
        """ Returns all services """
        return self.driver.get_all()

    def get_page(self, marker, limit):
        """ Get one page of services list """
        return self.driver.get_page(marker, limit)

    def get_page_markers(self, marker, limit):
        """ Calculate pagination markers for services list """
        return self.driver.get_page_markers(marker, limit)

    def get_by_name_and_type(self, name, service_type):
        """ Returns service by name and type """
        return self.driver.get_by_name_and_type(name, service_type)

    # pylint: disable=E1103
    def update(self, service):
        """ Update service """
        return self.driver.update(service['id'], service)

    def delete(self, service_id):
        """ Delete service """
        self.driver.delete(service_id)

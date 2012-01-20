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

""" EndpointTemplate manager module """

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.ENDPOINT_TEMPLATE

    def create(self, obj):
        """ Create a new Endpoint Template """
        return self.driver.create(obj)

    def get_all(self):
        """ Returns all endpoint templates """
        return self.driver.get_all()

    def get(self, endpoint_template_id):
        """ Returns Endpoint Template by ID """
        return self.driver.get(endpoint_template_id)

    def get_page(self, marker, limit):
        """ Get one page of endpoint template list """
        return self.driver.get_page(marker, limit)

    def get_page_markers(self, marker, limit):
        """ Calculate pagination markers for endpoint template list """
        return self.driver.get_page_markers(marker, limit)

    def get_by_service(self, service_id):
        """ Returns Endpoint Templates by service """
        return self.driver.get_by_service(service_id)

    def get_by_service_get_page(self, service_id, marker, limit):
        """ Get one page of endpoint templates by service"""
        return self.driver.get_by_service_get_page(service_id, marker, limit)

    def get_by_service_get_page_markers(self, service_id, marker, limit):
        """ Calculate pagination markers for endpoint templates by service """
        return self.driver.get_by_service_get_page_markers(service_id, marker,
                limit)

    def update(self, endpoint_template):
        """ Update Endpoint Template """
        return self.driver.update(endpoint_template['id'], endpoint_template)

    def delete(self, endpoint_template_id):
        """ Delete Endpoint Template """
        self.driver.delete(endpoint_template_id)

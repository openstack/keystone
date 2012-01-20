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

""" Endpoint manager module """

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.ENDPOINT_TEMPLATE

    def endpoint_get_by_endpoint_template(self, endpoint_template_id):
        """ Get all endpoints by endpoint template """
        return self.driver.endpoint_get_by_endpoint_template(
                endpoint_template_id)

    def delete(self, endpoint_id):
        """ Delete Endpoint """
        self.driver.endpoint_delete(endpoint_id)

    def endpoint_get_by_tenant_get_page(self, tenant_id, marker, limit):
        """ Get endpoints by tenant """
        return self.driver.endpoint_get_by_tenant_get_page(
                    tenant_id, marker, limit)

    def endpoint_get_by_tenant_get_page_markers(self, tenant_id, marker,
                                                limit):
        return self.driver.endpoint_get_by_tenant_get_page_markers(
                    tenant_id, marker, limit)

    def create(self, endpoint):
        """ Create a new Endpoint """
        return self.driver.endpoint_add(endpoint)

    def get(self, endpoint_id):
        """ Returns Endpoint by ID """
        return self.driver.endpoint_get(endpoint_id)

    # pylint: disable=E1103
    def get_by_ids(self, endpoint_template_id, tenant_id):
        """ Returns Endpoint by ID """
        return self.driver.endpoint_get_by_ids(endpoint_template_id, tenant_id)

    # pylint: disable=E1103
    def get_all(self):
        """ Returns all Endpoint Templates """
        return self.driver.endpoint_get_all()

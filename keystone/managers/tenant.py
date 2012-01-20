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

""" Tenant manager module

TODO: move functionality into here. Ex:

    def get_tenant(self, context, tenant_id):
        '''Return info for a tenant if it is valid.'''
        return self.driver.get(tenant_id)
"""

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.TENANT

    def create(self, tenant):
        return self.driver.create(tenant)

    def get(self, tenant_id):
        """ Returns tenant by ID """
        return self.driver.get(tenant_id)

    def get_by_name(self, name):
        """ Returns tenant by name """
        return self.driver.get_by_name(name=name)

    def get_all(self):
        """ Returns all tenants """
        return self.driver.get_all()

    def get_page(self, marker, limit):
        """ Get one page of tenants """
        return self.driver.get_page(marker, limit)

    def get_page_markers(self, marker, limit):
        """ Calculate pagination markers for tenant list """
        return self.driver.get_page_markers(marker, limit)

    def list_for_user_get_page(self, user_id, marker, limit):
        return self.driver.list_for_user_get_page(user_id, marker, limit)

    def list_for_user_get_page_markers(self, user_id, marker, limit):
        return self.driver.list_for_user_get_page_markers(user_id, marker,
                                                          limit)

    def update(self, tenant):
        """ Update tenant """
        return self.driver.update(tenant['id'], tenant)

    def delete(self, tenant_id):
        self.driver.delete(tenant_id)

    def get_all_endpoints(self, tenant_id):
        return self.driver.get_all_endpoints(tenant_id)

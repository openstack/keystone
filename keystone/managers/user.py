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

""" User manager module """

import logging

import keystone.backends.api as api

LOG = logging.getLogger(__name__)


class Manager(object):
    def __init__(self):
        self.driver = api.USER

    def create(self, user):
        """ Create user from dict or model, assign id if not there """
        return self.driver.create(user)

    def get(self, user_id):
        """ Returns user by ID """
        return self.driver.get(user_id)

    def get_by_name(self, name):
        """ Returns user by name """
        return self.driver.get_by_name(name=name)

    def get_by_email(self, email):
        """ Returns user by email """
        return self.driver.get_by_email(email=email)

    def get_all(self):
        """ Returns all users """
        return self.driver.get_all()

    def users_get_page(self, marker, limit):
        """ Get one page of users list """
        return self.driver.users_get_page(marker, limit)

    def users_get_page_markers(self, marker, limit):
        """ Calculate pagination markers for users list """
        return self.driver.users_get_page_markers(marker, limit)

    def get_by_tenant(self, user_id, tenant_id):
        """ Get user if associated with tenant, else None """
        return self.driver.get_by_tenant(user_id, tenant_id)

    def users_get_by_tenant_get_page(self, tenant_id, role_id, marker, limit):
        """ Get one page of users list for a tenant """
        return self.driver.users_get_by_tenant_get_page(
            tenant_id, role_id, marker, limit)

    def users_get_by_tenant_get_page_markers(self, tenant_id, role_id,
                                             marker, limit):
        """ Calculate pagination markers for users list on a tenant """
        return self.driver.users_get_by_tenant_get_page_markers(
                    tenant_id, role_id, marker, limit)

    def update(self, user):
        """ Update user """
        return self.driver.update(user['id'], user)

    def delete(self, user_id):
        self.driver.delete(user_id)

    def check_password(self, user_id, password):
        return self.driver.check_password(user_id, password)

    def user_role_add(self, values):
        self.driver.user_role_add(values)

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

""" Role-Grant manager module """

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.ROLE

    #
    # Role-Grant Methods
    #
    def rolegrant_get_page(self, user_id, tenant_id, marker, limit):
        """ Get one page of role grant list """
        return self.driver.rolegrant_get_page(user_id, tenant_id, marker,
                                                                        limit)

    def rolegrant_get_page_markers(self, user_id, tenant_id, marker, limit):
        """ Calculate pagination markers for role grants list """
        return self.driver.rolegrant_get_page_markers(user_id, tenant_id,
                                                                marker, limit)

    def list_global_roles_for_user(self, user_id):
        return self.driver.list_global_roles_for_user(user_id)

    def list_tenant_roles_for_user(self, user_id, tenant_id):
        return self.driver.list_tenant_roles_for_user(user_id, tenant_id)

    def rolegrant_list_by_role(self, role_id):
        return self.driver.rolegrant_list_by_role(role_id)

    def rolegrant_get_by_ids(self, user_id, role_id, tenant_id):
        return self.driver.rolegrant_get_by_ids(user_id, role_id, tenant_id)

    def rolegrant_delete(self, grant_id):
        return self.driver.rolegrant_delete(grant_id)

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

""" Token manager module """

import logging

import keystone.backends.api as api

LOG = logging.getLogger(__name__)


class Manager(object):
    def __init__(self):
        self.driver = api.TOKEN

    def create(self, token):
        return self.driver.create(token)

    # pylint: disable=E1103
    def update(self, id, token):
        return self.driver.update(id, token)

    def get(self, token_id):
        """ Returns token by ID """
        return self.driver.get(token_id)

    def get_all(self):
        """ Returns all tokens """
        return self.driver.get_all()

    def find(self, user_id, tenant_id=None):
        """ Finds token by user ID and, optionally, tenant ID

        :param user_id: user id as a string
        :param tenant_id: tenant id as a string (optional)
        :returns: Token object or None
        :raises: RuntimeError is user_id is None
        """
        if user_id is None:
            raise RuntimeError("User ID is required when looking up tokens")
        if tenant_id:
            return self.driver.get_for_user_by_tenant(user_id, tenant_id)
        else:
            return self.driver.get_for_user(user_id)

    def delete(self, token_id):
        self.driver.delete(token_id)

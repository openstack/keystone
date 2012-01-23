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

""" Credential manager module """

import logging

import keystone.backends.api as api

logger = logging.getLogger(__name__)  # pylint: disable=C0103


class Manager(object):
    def __init__(self):
        self.driver = api.CREDENTIALS

    def create(self, token):
        return self.driver.create(token)

    def update(self, id, credential):
        return self.driver.update(id, credential)

    def get(self, credential_id):
        return self.driver.get(credential_id)

    def get_all(self):
        return self.driver.get_all()

    def get_by_access(self, access):
        return self.driver.get_by_access(access)

    def delete(self, credential_id):
        return self.driver.delete(credential_id)

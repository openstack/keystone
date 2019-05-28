# Copyright 2019 SUSE Linux GmbH
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

"""List access rules."""

from keystone.common import cache
from keystone.common import manager
import keystone.conf


CONF = keystone.conf.CONF
MEMOIZE = cache.get_memoization_decorator(group='access_rules_config')


class Manager(manager.Manager):

    driver_namespace = 'keystone.access_rules_config'
    _provides_api = 'access_rules_config_api'

    def __init__(self):
        super(Manager, self).__init__(CONF.access_rules_config.driver)

    def list_access_rules_config(self, service=None):
        """List access rules config.

        :param str service: filter by service type

        :returns: a list of configured access rules. Access rules are
                  permission objects composing of a service, a URL path, and an
                  HTTP method.

        """
        return self.driver.list_access_rules_config(service)

    @MEMOIZE
    def check_access_rule(self, service, request_path, request_method):
        """Check access rule.

        :param str service: service type of rule to check
        :param str request_path: endpoint path to check
        :param str request_method: API HTTP method to check

        :returns: boolean indicating whether the rule matches one of the
                  configured access rules

        """
        return self.driver.check_access_rule(service, request_path,
                                             request_method)

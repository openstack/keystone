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
import abc

import stevedore

import keystone.conf
from keystone.i18n import _

CONF = keystone.conf.CONF


def load_driver(driver_name, *args):
    namespace = 'keystone.unified_limit.model'
    try:
        driver_manager = stevedore.DriverManager(namespace,
                                                 driver_name,
                                                 invoke_on_load=True,
                                                 invoke_args=args)
        return driver_manager.driver
    except stevedore.exception.NoMatches:
        msg = (_('Unable to find %(name)r driver in %(namespace)r.'))
        raise ImportError(msg % {'name': driver_name, 'namespace': namespace})


class ModelBase(object, metaclass=abc.ABCMeta):
    """Interface for a limit model driver."""

    NAME = None
    DESCRIPTION = None
    MAX_PROJECT_TREE_DEPTH = None

    def check_limit(self, limits):
        """Check the new creating or updating limits if satisfy the model.

        :param limits: A list of the limit references to be checked.
        :type limits: A list of the limits. Each limit is a dictionary
                      reference containing all limit attributes.

        :raises keystone.exception.InvalidLimit: If any of the input limits
            doesn't satisfy the limit model.

        """
        raise NotImplementedError()

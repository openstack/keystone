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

from keystone.limit.models import flat


def get_enforcement_model_from_config(enforcement_model):
    """Factory that returns an enforcement model object based on configuration.

    :param enforcement_model str: A string, usually from a configuration
                                  option, representing the name of the
                                  enforcement model
    :returns: an `Model` object

    """
    # NOTE(lbragstad): The configuration option set is strictly checked by the
    # ``oslo.config`` object. If someone passes in a garbage value, it will
    # fail before it gets to this point.
    if enforcement_model == 'flat':
        return flat.Model()

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

import keystone.conf


CONF = keystone.conf.CONF


def symptom_debug_mode_is_enabled():
    """Debug mode should be set to False.

    Debug mode can be used to get more information back when trying to isolate
    a problem, but it is not recommended to be enabled when running a
    production environment.

    Ensure `keystone.conf debug` is set to False
    """
    return CONF.debug

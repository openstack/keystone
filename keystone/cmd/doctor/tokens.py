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


def symptom_unreasonable_max_token_size():
    """`keystone.conf [DEFAULT] max_token_size` should be adjusted.

    This option is intended to protect keystone from unreasonably sized tokens,
    where "reasonable" is mostly dependent on the `keystone.conf [token]
    provider` that you're using. If you're using one of the following token
    providers, then you should set `keystone.conf [DEFAULT] max_token_size`
    accordingly:

    - For Fernet, set `keystone.conf [DEFAULT] max_token_size = 255`, because
      Fernet tokens should never exceed this length in most deployments.
      However, if you are also using `keystone.conf [identity] driver = ldap`,
      Fernet tokens may not be built using an efficient packing method,
      depending on the IDs returned from LDAP, resulting in longer Fernet
      tokens (adjust your `max_token_size` accordingly).
    """
    return ('fernet' in CONF.token.provider and CONF.max_token_size > 255)
